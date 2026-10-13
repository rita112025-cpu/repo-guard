"""檔名 / 大小 / 內容掃描。Finding 只存「遮罩後」的片段，原始秘密與關鍵字不會離開本模組。"""

from __future__ import annotations

import fnmatch
import re
from collections import Counter
from dataclasses import dataclass, field

from . import rules as R
from .config import Config
from .git_utils import Entry, SkipFile

MAX_FINDINGS_PER_FILE_RULE = 20  # 同一檔案同一規則最多列出幾筆，其餘只計數


@dataclass
class Finding:
    rule: str
    level: str
    path: str
    message: str
    line: int | None = None
    snippet: str | None = None  # 已遮罩
    ref: str | None = None  # commit 短 hash

    def key(self) -> tuple:
        return (self.rule, self.path, self.line, self.snippet, self.ref)


@dataclass
class ScanResult:
    mode: str
    findings: list[Finding] = field(default_factory=list)
    allowlisted: list[tuple[Finding, str]] = field(default_factory=list)  # (結果, 放行原因)
    skipped: list[tuple[str, str]] = field(default_factory=list)  # (路徑, 原因)
    omitted: Counter = field(default_factory=Counter)  # (等級) -> 未列出的筆數
    notes: list[str] = field(default_factory=list)
    scanned: int = 0
    no_head: bool = False  # staged 模式且 repo 尚無任何 commit（git restore --staged 無法使用）

    @property
    def block_count(self) -> int:
        return sum(1 for f in self.findings if f.level == R.BLOCK) + self.omitted[R.BLOCK]

    @property
    def warn_count(self) -> int:
        return sum(1 for f in self.findings if f.level == R.WARN) + self.omitted[R.WARN]


# --- 遮罩 -------------------------------------------------------------------

def mask_secret(value: str) -> str:
    """秘密只顯示前 4 字元 + ***。"""
    return value[:4] + "***"


def mask_tw_id(value: str) -> str:
    """身分證只顯示首字母 + ****** + 末 2 碼。"""
    return value[0] + "******" + value[-2:]


def mask_email(value: str) -> str:
    local, _, domain = value.partition("@")
    return local[:1] + "***@" + domain


class Sanitizer:
    """把輸出用字串中的自訂關鍵字換成「[關鍵字 #n]」（檔名也可能含客戶名）。"""

    def __init__(self, keywords: list[str]) -> None:
        self._pairs = [(re.compile(re.escape(k), re.IGNORECASE), f"[關鍵字 #{n}]")
                       for n, k in enumerate(keywords, 1)]

    def clean(self, text: str) -> str:
        for rx, label in self._pairs:
            text = rx.sub(label, text)
        return text


# --- 檔名 / 大小規則 ---------------------------------------------------------

def check_name(path: str, cfg: Config) -> list[Finding]:
    out: list[Finding] = []
    name = path.rsplit("/", 1)[-1]
    low = name.lower()

    if cfg.rule_enabled("R1"):
        for ext in R.FORBIDDEN_EXTENSIONS:
            if low.endswith(ext):
                out.append(Finding("R1", R.BLOCK, path, f"禁止的副檔名 {ext}（repo 不放工作資料）"))
                break
        else:
            for ext in R.WARN_EXTENSIONS:
                if low.endswith(ext):
                    out.append(Finding("R1", cfg.pdf_level, path,
                                       f"{ext} 檔可能含工作資料，請確認內容可公開"))

    if cfg.rule_enabled("R3") and low not in R.SECRET_FILENAME_EXCLUDES:
        for pat in R.SECRET_FILENAME_PATTERNS:
            if fnmatch.fnmatchcase(low, pat):
                out.append(Finding("R3", R.BLOCK, path, f"機密檔名（符合 {pat}），可能含金鑰或憑證"))
                break
    return out


def check_size(path: str, size: int, cfg: Config) -> list[Finding]:
    if cfg.rule_enabled("R2") and size > cfg.max_file_size_bytes:
        return [Finding("R2", R.BLOCK, path,
                        f"檔案大小 {size / 1048576:.1f} MB，超過門檻 {cfg.max_file_size_mb:g} MB")]
    return []


# --- 內容掃描 ---------------------------------------------------------------

def decode_text(data: bytes) -> tuple[str | None, str | None]:
    """回傳 (文字, 跳過原因)。依序嘗試 UTF-8、UTF-8 BOM、cp950；二進位或無法解碼則跳過。"""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):  # UTF-16 BOM（Windows PowerShell 的 > 輸出）
        try:
            return data.decode("utf-16"), None
        except UnicodeDecodeError:
            return None, "二進位檔或無法解碼"
    if b"\0" in data[:8192]:
        return None, "二進位檔"
    for enc in ("utf-8-sig" if data.startswith(b"\xef\xbb\xbf") else "utf-8", "cp950"):
        try:
            return data.decode(enc), None
        except UnicodeDecodeError:
            continue
    return None, "無法以 UTF-8 / cp950 解碼"


def _scan_line(line: str, lineno: int, path: str, enabled: frozenset[str],
               kw_lower: tuple[str, ...]) -> list[Finding]:
    out: list[Finding] = []

    if "R4" in enabled:
        for sp in R.SECRET_PATTERNS:
            for m in sp.regex.finditer(line):
                val = m.group(sp.group)
                if sp.validator == "generic_value" and not R.generic_value_plausible(val):
                    continue
                out.append(Finding("R4", R.BLOCK, path, f"疑似{sp.label}", lineno, mask_secret(val)))

    if "R5-ID" in enabled:
        for m in R.TW_ID_REGEX.finditer(line):
            if R.tw_id_valid(m.group()):
                out.append(Finding("R5-ID", R.BLOCK, path, "疑似台灣身分證字號（檢查碼正確）",
                                   lineno, mask_tw_id(m.group())))
    if "R5-PHONE" in enabled:
        for m in R.TW_PHONE_REGEX.finditer(line):
            out.append(Finding("R5-PHONE", R.WARN, path, "疑似台灣手機號碼", lineno, mask_secret(m.group())))
    if "R5-EMAIL" in enabled:
        for m in R.EMAIL_REGEX.finditer(line):
            out.append(Finding("R5-EMAIL", R.WARN, path, "Email 位址", lineno, mask_email(m.group())))

    if "R6" in enabled:
        low = line.lower()
        for n, kw in enumerate(kw_lower, 1):
            if kw in low:
                label = f"[關鍵字 #{n}]"
                out.append(Finding("R6", R.BLOCK, path, "含自訂關鍵字", lineno, label))
    return out


def scan_text(path: str, text: str, cfg: Config,
              *, keyword_lowers: tuple[str, ...] | None = None) -> list[Finding]:
    enabled = frozenset(
        rid for rid in ("R4", "R5-ID", "R5-PHONE", "R5-EMAIL", "R6")
        if cfg.rule_enabled(rid) and (rid != "R6" or cfg.keywords)
    )
    kw_lower = keyword_lowers if keyword_lowers is not None else tuple(k.lower() for k in cfg.keywords)
    out: list[Finding] = []
    for i, line in enumerate(text.split("\n"), 1):
        out.extend(_scan_line(line, i, path, enabled, kw_lower))

    # R6-CFG：repo 內的關鍵字設定檔
    parts = path.split("/")
    in_guard_dir = len(parts) >= 2 and parts[-2] == ".repo-guard" and parts[-1] == "config.toml"
    if cfg.rule_enabled("R6-CFG") and (in_guard_dir or parts[-1] == ".repo-guard.toml"):
        m = re.search(r"(?m)^\s*keywords\s*=", text)
        if m:
            lineno = text.count("\n", 0, m.start()) + 1
            out.append(Finding("R6-CFG", R.WARN, path, "此設定檔含關鍵字清單，不應放進 repo", lineno))
    return out


# --- 主流程 -----------------------------------------------------------------

def scan_entries(entries: list[Entry], cfg: Config, result: ScanResult, *, names_only: bool = False) -> ScanResult:
    keyword_lowers = tuple(k.lower() for k in cfg.keywords)
    for e in entries:
        result.scanned += 1
        raw: list[Finding] = []
        size: int | None = None
        data: bytes | None = None

        if names_only:
            raw.extend(f for f in check_name(e.path, cfg) if f.rule in ("R1", "R3"))
        else:
            raw.extend(check_name(e.path, cfg))
            try:
                size, data = e.fetch(R.CONTENT_SCAN_LIMIT_BYTES)
            except SkipFile as s:
                result.skipped.append((e.path, str(s)))
            else:
                raw.extend(check_size(e.path, size, cfg))
                if data is None:
                    result.skipped.append((e.path, "超過內容掃描大小上限"))
                else:
                    text, why = decode_text(data)
                    if text is None:
                        result.skipped.append((e.path, why or "無法解碼"))
                    else:
                        raw.extend(scan_text(e.path, text, cfg, keyword_lowers=keyword_lowers))

        per_rule: Counter = Counter()
        seen: set[tuple] = set()
        for f in raw:
            f.ref = e.ref
            if f.key() in seen:
                continue
            seen.add(f.key())
            entry = cfg.allowing(f.path, f.rule)
            if entry is not None:
                result.allowlisted.append((f, entry.reason))
                continue
            per_rule[f.rule] += 1
            if per_rule[f.rule] > MAX_FINDINGS_PER_FILE_RULE:
                result.omitted[f.level] += 1
            else:
                result.findings.append(f)
    return result
