"""git 呼叫與待掃描檔案的來源。一律用參數列表呼叫 subprocess，不使用 shell；全部唯讀。"""

from __future__ import annotations

import os
import stat
import subprocess
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

ZERO_SHA_CHARS = frozenset("0")


class GitError(Exception):
    """git 執行失敗或不在 repo 內（結束碼 2）。"""


def is_zero_sha(sha: str) -> bool:
    return bool(sha) and set(sha) <= ZERO_SHA_CHARS


def run_git(args: list[str], cwd: Path, *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    try:
        proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, check=False)
    except FileNotFoundError:
        raise GitError("找不到 git 指令，請先安裝 git 並確認在 PATH 中") from None
    if check and proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise GitError(f"git {' '.join(args[:2])} 失敗：{msg[0] if msg else '未知錯誤'}")
    return proc


def _split_z(data: bytes) -> list[str]:
    return [p.decode("utf-8", "surrogateescape") for p in data.split(b"\0") if p]


def repo_toplevel(cwd: Path) -> Path:
    proc = run_git(["rev-parse", "--show-toplevel"], cwd, check=False)
    if proc.returncode != 0:
        raise GitError("目前目錄不在 git repo 內")
    return Path(proc.stdout.decode("utf-8", "replace").strip())


def hooks_dir(repo: Path) -> Path:
    """用 git rev-parse --git-path hooks 取得 hooks 目錄（支援 core.hooksPath）。"""
    out = run_git(["rev-parse", "--git-path", "hooks"], repo).stdout.decode("utf-8", "replace").strip()
    p = Path(out)
    return p if p.is_absolute() else (repo / p)


def is_ignored(repo: Path, rel_path: str) -> bool:
    return run_git(["check-ignore", "-q", "--", rel_path], repo, check=False).returncode == 0


# --- 讀取內容 ---------------------------------------------------------------

class SkipFile(Exception):
    """該檔案不掃描內容，訊息為原因。"""


FetchResult = tuple[int, bytes | None]  # (大小, 內容；超過上限時為 None)


class BlobReader:
    """用單一 `git cat-file --batch` 程序讀取 blob，避免每個檔案開一個程序。"""

    def __init__(self, cwd: Path) -> None:
        self._p = subprocess.Popen(
            ["git", "cat-file", "--batch"], cwd=cwd,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        )

    def fetch(self, spec: str, limit: int) -> FetchResult:
        if "\n" in spec:
            raise SkipFile("檔名含換行字元，無法讀取")
        assert self._p.stdin is not None and self._p.stdout is not None
        self._p.stdin.write(spec.encode("utf-8", "surrogateescape") + b"\n")
        self._p.stdin.flush()
        header = self._p.stdout.readline().decode("utf-8", "replace").split()
        if len(header) == 2 and header[1] == "missing":
            raise SkipFile("在 git 物件庫中找不到")
        if len(header) != 3:
            raise SkipFile("無法讀取（物件名稱不明確）")
        _sha, kind, size_s = header
        size = int(size_s)
        out = self._p.stdout
        data: bytes | None
        if size <= limit:
            data = out.read(size)
        else:
            data = None
            left = size
            while left:
                chunk = out.read(min(left, 1 << 20))
                if not chunk:
                    break
                left -= len(chunk)
        out.read(1)  # 結尾換行
        if kind != "blob":
            raise SkipFile("不是一般檔案（可能是子模組）")
        return size, data

    def close(self) -> None:
        try:
            if self._p.stdin:
                self._p.stdin.close()
            self._p.wait(timeout=10)
        except Exception:  # noqa: BLE001
            self._p.kill()
        finally:
            if self._p.stdout:
                self._p.stdout.close()

    def __enter__(self) -> BlobReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


@dataclass
class Entry:
    path: str  # repo 內的 posix 相對路徑
    fetch: Callable[[int], FetchResult]  # (limit) -> (size, data|None)；失敗拋 SkipFile
    ref: str | None = None  # commit 短 hash（pre-push / history）


def staged_entries(repo: Path, reader: BlobReader) -> list[Entry]:
    out = run_git(["diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"], repo).stdout
    entries = []
    for path in _split_z(out):
        entries.append(Entry(path, lambda limit, p=path: reader.fetch(f":0:{p}", limit)))
    return entries


def _disk_fetch(repo: Path, rel: str, limit: int) -> FetchResult:
    full = repo / rel
    try:
        st = os.lstat(full)
    except FileNotFoundError:
        raise SkipFile("檔案已不存在於工作目錄") from None
    except OSError as e:
        raise SkipFile(f"無法讀取（{e.strerror or type(e).__name__}）") from None
    if stat.S_ISLNK(st.st_mode):
        raise SkipFile("符號連結（不追蹤）")
    if not stat.S_ISREG(st.st_mode):
        raise SkipFile("不是一般檔案（目錄或子模組）")
    if st.st_size > limit:
        return st.st_size, None
    try:
        return st.st_size, full.read_bytes()
    except OSError as e:
        raise SkipFile(f"無法讀取（{e.strerror or type(e).__name__}）") from None


def all_entries(repo: Path) -> list[Entry]:
    out = run_git(["ls-files", "-co", "--exclude-standard", "-z"], repo).stdout
    seen: set[str] = set()
    entries = []
    for path in _split_z(out):
        if path in seen:
            continue
        seen.add(path)
        entries.append(Entry(path, lambda limit, p=path: _disk_fetch(repo, p, limit)))
    return entries


def _parse_log_raw(data: bytes) -> Iterator[tuple[str, str, str, str]]:
    """解析 `git log --raw -z --format=%x01%H`，產生 (commit, path, blob_sha, new_mode)。"""
    toks = data.split(b"\0")
    i = 0
    commit = ""
    while i < len(toks):
        tok = toks[i].lstrip(b"\n")
        i += 1
        if not tok:
            continue
        if tok.startswith(b"\x01"):
            commit = tok[1:].decode("ascii", "replace").strip()
        elif tok.startswith(b":"):
            fields = tok[1:].decode("ascii", "replace").split()
            new_mode, new_sha, status = fields[1], fields[3], fields[4]
            npaths = 2 if status[0] in "RC" else 1
            paths = toks[i:i + npaths]
            i += npaths
            if paths:
                yield commit, paths[-1].decode("utf-8", "surrogateescape"), new_sha, new_mode


def _log_entries(repo: Path, reader: BlobReader, rev_args: list[str]) -> list[Entry]:
    out = run_git(
        ["log", "--no-merges", "--root", "--raw", "--no-abbrev", "-z", "--diff-filter=ACMR",
         "--format=%x01%H", *rev_args],
        repo,
    ).stdout
    seen: set[tuple[str, str]] = set()
    entries = []
    for commit, path, sha, mode in _parse_log_raw(out):
        if (path, sha) in seen:
            continue
        seen.add((path, sha))
        if mode == "160000":  # 子模組
            continue
        entries.append(Entry(path, lambda limit, s=sha: reader.fetch(s, limit), commit[:8]))
    return entries


def history_entries(repo: Path, reader: BlobReader) -> list[Entry]:
    return _log_entries(repo, reader, ["--all"])


@dataclass
class PushRef:
    local_ref: str
    local_sha: str
    remote_ref: str
    remote_sha: str


def parse_prepush_stdin(text: str) -> list[PushRef]:
    refs = []
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 4:
            raise GitError(f"pre-push 標準輸入第 {n} 行格式不符（應為 4 個欄位）")
        refs.append(PushRef(*parts))
    return refs


def prepush_entries(repo: Path, reader: BlobReader, refs: Iterable[PushRef]) -> tuple[list[Entry], list[str]]:
    """回傳 (entries, notes)。刪除分支跳過；新分支掃描 `<sha> --not --remotes`。"""
    entries: list[Entry] = []
    notes: list[str] = []
    seen: set[tuple[str, str]] = set()
    for r in refs:
        if is_zero_sha(r.local_sha):
            notes.append(f"{r.remote_ref}：刪除分支，已跳過")
            continue
        if is_zero_sha(r.remote_sha):
            rev = [r.local_sha, "--not", "--remotes"]
        else:
            probe = run_git(["cat-file", "-e", f"{r.remote_sha}^{{commit}}"], repo, check=False)
            if probe.returncode == 0:
                rev = [f"{r.remote_sha}..{r.local_sha}"]
            else:
                rev = [r.local_sha, "--not", "--remotes"]
                notes.append(f"{r.remote_ref}：本機沒有遠端 commit，改以 --not --remotes 判斷未推送範圍")
        for e in _log_entries(repo, reader, rev):
            # 同一 blob 在多個 ref 重複出現時只掃一次（以路徑 + blob 去重）
            key = (e.path, e.ref or "")
            if key in seen:
                continue
            seen.add(key)
            entries.append(e)
    return entries, notes
