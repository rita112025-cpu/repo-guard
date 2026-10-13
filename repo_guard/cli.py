"""命令列入口。結束碼：0 無 BLOCK；1 有 BLOCK；2 工具或設定錯誤。"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import BinaryIO

from . import __version__, hooks
from .config import Config, ConfigError, describe, load_config
from .git_utils import (
    BlobReader, GitError, all_entries, history_entries, hooks_dir, is_ignored,
    parse_prepush_stdin, prepush_entries, repo_toplevel, run_git, staged_entries,
)
from .report import RENDERERS, render_config
from .rules import BLOCK, WARN
from .scanners import Finding, Sanitizer, ScanResult, scan_entries


class ToolError(Exception):
    """其他工具錯誤（結束碼 2）。"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="repo-guard", description="Git commit / push 前的資料外洩檢查（唯讀、不連網）")
    p.add_argument("--version", action="version", version=f"repo-guard {__version__}")
    p.add_argument("-C", dest="directory", metavar="PATH", default=".", help="在指定目錄執行（預設為目前目錄）")
    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scan", help="掃描檔案")
    g = sc.add_mutually_exclusive_group(required=True)
    g.add_argument("--staged", action="store_true", help="掃描已暫存的變更（git diff --cached）")
    g.add_argument("--pre-push", nargs=2, metavar=("REMOTE_NAME", "REMOTE_URL"),
                   help="Git pre-push 模式，從 stdin 讀取 ref 清單")
    g.add_argument("--all", action="store_true", help="掃描 git ls-files -co --exclude-standard 的所有檔案")
    g.add_argument("--history", action="store_true", help="掃描所有 commit 中出現過的檔案")
    sc.add_argument("--names-only", action="store_true", help="（搭配 --history）只檢查檔名規則 R1、R3")
    sc.add_argument("--format", choices=sorted(RENDERERS), default="text")
    sc.add_argument("--report", metavar="PATH", help="另外把報告寫入此檔案（UTF-8）")
    sc.add_argument("--with-gitleaks", action="store_true", help="若已安裝 gitleaks，合併它的結果")

    cf = sub.add_parser("config", help="設定相關")
    cf.add_argument("--show", action="store_true", required=True, help="顯示合併後設定（關鍵字只顯示數量）")
    cf.add_argument("--format", choices=["text", "json"], default="text")

    ih = sub.add_parser("install-hooks", help="安裝 pre-commit 與 pre-push hook")
    ih.add_argument("--force", action="store_true", help="覆寫既有 hook（先備份為 <name>.bak-YYYYMMDD-HHMMSS）")
    sub.add_parser("uninstall-hooks", help="移除本工具安裝的 hook")
    return p


# --- gitleaks（選用）---------------------------------------------------------

def _gitleaks_version(exe: str) -> tuple[int, ...] | None:
    """執行 `gitleaks version` 並解析成數字元組；失敗回傳 None。"""
    try:
        proc = subprocess.run([exe, "version"], capture_output=True, check=False, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", proc.stdout.decode("utf-8", "replace"))
    return tuple(int(x) for x in m.groups(default="0")) if m else None


def _gitleaks_cmd(exe: str, mode: str, repo: Path, common: list[str],
                  version: tuple[int, ...] | None) -> list[str]:
    """8.19.0 起 protect / detect 已棄用，改用 git / dir 子命令；版本未知時視為新版。"""
    if version is not None and version < (8, 19, 0):
        if mode == "staged":
            return [exe, "protect", "--staged", *common, "--source", str(repo)]
        if mode == "all":
            return [exe, "detect", "--no-git", *common, "--source", str(repo)]
        return [exe, "detect", *common, "--source", str(repo)]
    if mode == "staged":
        return [exe, "git", "--staged", *common, str(repo)]
    if mode == "all":
        return [exe, "dir", *common, str(repo)]
    return [exe, "git", *common, str(repo)]


def _run_gitleaks(repo: Path, mode: str, result: ScanResult) -> None:
    exe = shutil.which("gitleaks")
    if exe is None:
        result.notes.append("--with-gitleaks：系統未安裝 gitleaks（或不在 PATH），已略過；僅使用內建規則。"
                            "安裝說明見 https://github.com/gitleaks/gitleaks")
        return
    with tempfile.TemporaryDirectory(prefix="repo-guard-") as tmp:
        report = Path(tmp) / "gitleaks.json"
        common = ["--redact", "--no-banner", "--report-format", "json", "--report-path", str(report)]
        cmd = _gitleaks_cmd(exe, mode, repo, common, _gitleaks_version(exe))
        if mode == "pre-push":
            result.notes.append("gitleaks 在 pre-push 模式會掃描整個歷史，而非只掃未推送的 commit。")
        try:
            proc = subprocess.run(cmd, cwd=repo, capture_output=True, check=False, timeout=600)
        except (OSError, subprocess.TimeoutExpired) as e:
            result.notes.append(f"gitleaks 執行失敗（{type(e).__name__}），已略過。")
            return
        if proc.returncode not in (0, 1):
            result.notes.append(f"gitleaks 回傳非預期結束碼 {proc.returncode}，已略過其結果。")
            return
        try:
            items = json.loads(report.read_text(encoding="utf-8")) if report.exists() else []
        except (OSError, ValueError):
            result.notes.append("無法解析 gitleaks 的報告，已略過其結果。")
            return
    for it in items if isinstance(items, list) else []:
        raw_path = str(it.get("File", ""))
        try:
            rel = Path(raw_path).resolve().relative_to(repo.resolve()).as_posix()
        except (ValueError, OSError):
            rel = raw_path.replace("\\", "/")
        result.findings.append(Finding("GITLEAKS", BLOCK, rel, f"gitleaks 規則 {it.get('RuleID', '?')}",
                                       it.get("StartLine") or None, "[gitleaks 已遮罩]",
                                       str(it.get("Commit", ""))[:8] or None))


# --- R6-CFG：全域設定檔位於 repo 內 ------------------------------------------

def _check_global_config_in_repo(repo: Path, cfg: Config, result: ScanResult) -> None:
    if not (cfg.keywords and cfg.global_config_loaded and cfg.rule_enabled("R6-CFG") and cfg.global_config_path):
        return
    try:
        rel = cfg.global_config_path.resolve().relative_to(repo.resolve()).as_posix()
    except (ValueError, OSError):
        return
    if is_ignored(repo, rel):
        return
    if any(f.rule == "R6-CFG" and f.path == rel for f in result.findings):
        return  # 掃描內容時已回報同一個檔案
    f = Finding("R6-CFG", WARN, rel, "含關鍵字清單的全域設定檔位於此 repo 內且未被 .gitignore 排除")
    allowed = cfg.allowing(f.path, f.rule)
    if allowed:
        result.allowlisted.append((f, allowed.reason))
    else:
        result.findings.append(f)


# --- 指令 -------------------------------------------------------------------

def _emit(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()


def cmd_scan(args: argparse.Namespace, stdin: BinaryIO | None) -> int:
    if args.names_only and not args.history:
        raise ToolError("--names-only 只能搭配 --history 使用")
    repo = repo_toplevel(Path(args.directory))
    cfg = load_config(repo)
    san = Sanitizer(cfg.keywords)

    if args.staged:
        mode = "staged"
    elif args.pre_push:
        mode = "pre-push"
    elif args.all:
        mode = "all"
    else:
        mode = "history-names" if args.names_only else "history"
    result = ScanResult(mode=mode)
    if mode == "staged":
        result.no_head = run_git(["rev-parse", "--verify", "-q", "HEAD"], repo, check=False).returncode != 0

    with BlobReader(repo) as reader:
        if mode == "staged":
            entries = staged_entries(repo, reader)
        elif mode == "pre-push":
            data = (stdin if stdin is not None else sys.stdin.buffer).read()
            refs = parse_prepush_stdin(data.decode("utf-8", "replace"))
            entries, notes = prepush_entries(repo, reader, refs)
            result.notes.extend(notes)
        elif mode == "all":
            entries = all_entries(repo)
        else:
            entries = history_entries(repo, reader)
        scan_entries(entries, cfg, result, names_only=args.names_only)

    _check_global_config_in_repo(repo, cfg, result)
    if args.with_gitleaks:
        _run_gitleaks(repo, mode, result)
    if mode.startswith("history"):
        result.notes.append("歷史中的問題只能偵測、不能由本工具清除；已推送的內容請視為已外洩。")

    text = RENDERERS[args.format](result, san)
    _emit(text)
    if args.report:
        try:
            Path(args.report).write_text(text, encoding="utf-8")
        except OSError as e:
            raise ToolError(f"無法寫入報告 {args.report}（{e.strerror or type(e).__name__}）") from None
        sys.stderr.write(f"報告已寫入：{args.report}\n")
    return 1 if result.block_count else 0


def cmd_config(args: argparse.Namespace) -> int:
    try:
        repo: Path | None = repo_toplevel(Path(args.directory))
    except GitError:
        repo = None
    cfg = load_config(repo)
    san = Sanitizer(cfg.keywords)
    desc = describe(cfg)
    for a in desc["allowlist"]:
        a["path"], a["reason"] = san.clean(a["path"]), san.clean(a["reason"])
    _emit(render_config(desc, args.format))
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    repo = repo_toplevel(Path(args.directory))
    hdir = hooks_dir(repo)
    outcomes = hooks.install(hdir, force=args.force)
    label = {"installed": "已安裝", "updated": "已更新（原本就是 repo-guard 的 hook）",
             "backed-up": "已覆寫", "skipped": "未安裝"}
    _emit(f"hooks 目錄：{hdir}\n")
    failed = False
    for o in outcomes:
        _emit(f"  {o.name}：{label[o.status]}\n")
        if o.detail:
            _emit("    " + o.detail.replace("\n", "\n    ") + "\n")
        failed |= o.status == "skipped"
    return 2 if failed else 0


def cmd_uninstall(args: argparse.Namespace) -> int:
    repo = repo_toplevel(Path(args.directory))
    hdir = hooks_dir(repo)
    label = {"removed": "已移除", "absent": "不存在", "not-ours": "非 repo-guard 的 hook，保留不動"}
    _emit(f"hooks 目錄：{hdir}\n")
    for o in hooks.uninstall(hdir):
        _emit(f"  {o.name}：{label[o.status]}\n")
    return 0


def main(argv: list[str] | None = None, stdin: BinaryIO | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            return cmd_scan(args, stdin)
        if args.command == "config":
            return cmd_config(args)
        if args.command == "install-hooks":
            return cmd_install(args)
        return cmd_uninstall(args)
    except (ConfigError, GitError, ToolError) as e:
        sys.stderr.write(f"錯誤：{e}\n")
        return 2
    except Exception as e:  # noqa: BLE001  工具本身的非預期錯誤也用結束碼 2，不讓 hook 靜默通過
        if os.environ.get("REPO_GUARD_DEBUG"):
            raise
        sys.stderr.write(f"工具內部錯誤：{type(e).__name__}（設定 REPO_GUARD_DEBUG=1 可看詳細資訊）\n")
        return 2


def console_main() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    sys.exit(main())
