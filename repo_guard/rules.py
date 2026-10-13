"""所有檢查規則集中定義於此。每條規則附註說明來源或理由。

原則：token 格式只收錄有公開文件或業界通行的前綴，不自行發明；
長度不確定的格式只用「前綴 + 保守的最小長度」，並在註解標明。
"""

from __future__ import annotations

import re
from dataclasses import dataclass

BLOCK = "BLOCK"
WARN = "WARN"


@dataclass(frozen=True)
class Rule:
    id: str
    level: str  # 預設等級
    title: str
    note: str  # 規則來源 / 理由
    default_enabled: bool = True


RULES: dict[str, Rule] = {
    r.id: r
    for r in (
        Rule("R1", BLOCK, "禁止的副檔名",
             "公司規定 repo 只放程式，不放 Excel／資料庫／CAD／壓縮檔等工作資料。.pdf 預設只警告。"),
        Rule("R2", BLOCK, "檔案過大",
             "大檔案通常是資料、圖檔或打包檔；預設門檻 5 MB，可在設定檔調整。"),
        Rule("R3", BLOCK, "機密檔名",
             "此類檔名（.env、私鑰、憑證、服務帳號）幾乎一定含機密。.env.example 為範本，排除。"),
        Rule("R4", BLOCK, "疑似秘密字串",
             "掃描文字內容中的私鑰區塊、雲端／平台 token 前綴與通用密碼賦值。"),
        Rule("R5-ID", BLOCK, "台灣身分證字號",
             "通過官方檢查碼驗證才回報，降低誤報。"),
        Rule("R5-PHONE", WARN, "台灣手機號碼",
             "09 開頭共 10 碼。可能是公開客服電話，故只警告。"),
        Rule("R5-EMAIL", WARN, "Email 位址",
             "Email 在程式碼中很常見（作者資訊、範例），預設關閉，需要時在設定檔開啟。",
             default_enabled=False),
        Rule("R6", BLOCK, "自訂關鍵字",
             "客戶名、案名、廠商名等清單，只能放在全域設定（~/.repo-guard/config.toml）。"),
        Rule("R6-CFG", WARN, "含關鍵字清單的設定檔位於 repo 內",
             "關鍵字清單本身就是敏感資料，不應被 commit 或放在 repo 內且未被 .gitignore 排除。"),
        Rule("GITLEAKS", BLOCK, "gitleaks 回報",
             "由外部工具 gitleaks（--with-gitleaks）偵測，內容已由 gitleaks 遮罩。"),
    )
}

# 設定檔 / allowlist 可使用的規則 ID（含大類 R5）
CONFIG_RULE_IDS: frozenset[str] = frozenset(RULES) | {"R5"}


def rule_matches(entry_rule: str, finding_rule: str) -> bool:
    """allowlist 的規則 ID 是否涵蓋該結果（R5 涵蓋 R5-ID/R5-PHONE/R5-EMAIL）。"""
    return entry_rule == finding_rule or finding_rule.startswith(entry_rule + "-")


# --- R1 --------------------------------------------------------------------
# 來源：任務規格。以「檔名結尾」比對（小寫），因此 ".xlsx" 這類無主檔名的檔案也會命中。
FORBIDDEN_EXTENSIONS: tuple[str, ...] = (
    ".xlsx", ".xlsm", ".xls", ".csv",          # 試算表 / 報價、客戶資料
    ".db", ".sqlite", ".sqlite3", ".accdb", ".mdb",  # 資料庫
    ".dwg", ".dxf", ".rvt", ".rfa",            # CAD / BIM 圖檔
    ".bak", ".pst",                            # 備份、Outlook 信箱
    ".zip", ".7z", ".rar",                     # 壓縮檔（可能夾帶任何資料）
)
WARN_EXTENSIONS: tuple[str, ...] = (".pdf",)  # 預設 WARN，可由 pdf_level 改為 BLOCK

# --- R2 --------------------------------------------------------------------
DEFAULT_MAX_FILE_SIZE_MB = 5.0
# 內容掃描的大小上限（超過就只做檔名/大小檢查，避免把巨大檔案讀進記憶體）
CONTENT_SCAN_LIMIT_BYTES = 10 * 1024 * 1024

# --- R3 --------------------------------------------------------------------
# 以 basename、不分大小寫、fnmatch 風格比對。
SECRET_FILENAME_PATTERNS: tuple[str, ...] = (
    ".env", ".env.*", "id_rsa", "*.pem", "*.key", "*.p12", "*.pfx",
    "credentials*.json", "service-account*.json",
)
SECRET_FILENAME_EXCLUDES: tuple[str, ...] = (".env.example",)

# --- R4 --------------------------------------------------------------------


@dataclass(frozen=True)
class SecretPattern:
    label: str
    regex: re.Pattern[str]
    note: str
    group: int = 0  # 要遮罩的 capture group
    validator: str | None = None  # 目前只有 "generic_value"


SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern(
        "私鑰區塊",
        re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
        "PEM 格式私鑰開頭（RFC 7468）；涵蓋 RSA / EC / OPENSSH / ENCRYPTED 等。",
    ),
    SecretPattern(
        "AWS Access Key ID",
        re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
        "AWS 文件：Access Key ID 為 AKIA 開頭、共 20 字元的大寫英數。",
    ),
    SecretPattern(
        "GitHub token",
        re.compile(r"(?<![A-Za-z0-9_])(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
        "GitHub 公告的 token 前綴（ghp_ gho_ ghu_ ghs_ ghr_ 後接 36 字元；github_pat_ 為細粒度 token）。",
    ),
    SecretPattern(
        "Hugging Face token",
        re.compile(r"(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{30,}"),
        "hf_ 前綴；官方未公布固定長度，此處取保守下限 30 字元以避開一般變數名（經驗值）。",
    ),
    SecretPattern(
        "Slack token",
        re.compile(r"(?<![A-Za-z0-9_])xox[baprs]-[A-Za-z0-9-]{10,}"),
        "Slack token 前綴 xoxb- xoxa- xoxp- xoxr- xoxs-；後段長度取保守下限 10。",
    ),
    SecretPattern(
        "通用密碼／金鑰賦值",
        # 關鍵字（可前後帶識別字字元，如 DB_PASSWORD、api_key_prod）+ 可選引號 + = 或 : + 值（≥16 字元）
        re.compile(
            r"(?i)(?:api[_-]?key|secret|token|password)[A-Za-z0-9_\-]*[\"']?\s*[=:]\s*[\"']?"
            r"([^\s\"'`,;(){}<>\[\]]{16,})"
        ),
        "通用賦值：api_key / secret / token / password 後接 = 或 : 且值長度 ≥ 16。"
        "會略過明顯的識別字、變數引用與佔位字串。",
        group=1,
        validator="generic_value",
    ),
)

_PLACEHOLDER_WORDS = ("example", "your", "placeholder", "changeme", "change_me", "dummy", "sample", "xxxx", "****")
_LOWER_IDENT = re.compile(r"^[a-z_.\-]+$")
_UPPER_CONST = re.compile(r"^[A-Z_]+$")
_DOTTED_CHAIN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")


def generic_value_plausible(value: str) -> bool:
    """通用賦值的誤報過濾：看起來像識別字／變數引用／佔位字串的值不回報。"""
    if value.startswith(("$", "%", "@", "#", "{{")):
        return False
    low = value.lower()
    if any(w in low for w in _PLACEHOLDER_WORDS):
        return False
    if len(set(value)) <= 2:  # 如 "................"
        return False
    if _LOWER_IDENT.match(value) or _UPPER_CONST.match(value) or _DOTTED_CHAIN.match(value):
        return False
    return True


# --- R5 --------------------------------------------------------------------
# 台灣身分證字號：英文字母 + 性別碼（1 男 / 2 女）+ 7 碼流水號 + 1 碼檢查碼。
TW_ID_REGEX = re.compile(r"(?<![A-Za-z0-9])[A-Z][12]\d{8}(?!\d)")

# 演算法來源：內政部戶政司「身分證統一編號編碼規則」（公開規範）。
#   1. 首字母依下表換成兩位數（A=10 … Z=33，I=34、O=35、W=32、Z=33 等為官方特例順序）。
#   2. n = 十位數×1 + 個位數×9 + d1×8 + d2×7 + d3×6 + d4×5 + d5×4 + d6×3 + d7×2 + d8×1 + d9（檢查碼）。
#   3. n 能被 10 整除才是有效號碼。
_TW_LETTER_CODE = {
    "A": 10, "B": 11, "C": 12, "D": 13, "E": 14, "F": 15, "G": 16, "H": 17,
    "I": 34, "J": 18, "K": 19, "L": 20, "M": 21, "N": 22, "O": 35, "P": 23,
    "Q": 24, "R": 25, "S": 26, "T": 27, "U": 28, "V": 29, "W": 32, "X": 30,
    "Y": 31, "Z": 33,
}


def tw_id_valid(s: str) -> bool:
    if len(s) != 10 or s[0] not in _TW_LETTER_CODE or s[1] not in "12" or not s[1:].isdigit():
        return False
    code = _TW_LETTER_CODE[s[0]]
    total = code // 10 + (code % 10) * 9
    for i, ch in enumerate(s[1:9]):
        total += int(ch) * (8 - i)
    total += int(s[9])
    return total % 10 == 0


# 手機：09 開頭共 10 碼，容許 0912-345-678 / 0912 345 678 的分隔。
TW_PHONE_REGEX = re.compile(r"(?<!\d)09\d{2}[- ]?\d{3}[- ]?\d{3}(?!\d)")

# Email：保守的通用格式。
EMAIL_REGEX = re.compile(r"(?<![A-Za-z0-9._%+\-])[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
