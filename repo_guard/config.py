"""設定載入與合併。優先序：repo > 全域 > 預設。

- 全域：~/.repo-guard/config.toml（可用環境變數 REPO_GUARD_GLOBAL_CONFIG 指定其他路徑）
- repo：<repo 根目錄>/.repo-guard.toml（可 commit；禁止 keywords）
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .rules import CONFIG_RULE_IDS, DEFAULT_MAX_FILE_SIZE_MB, RULES, rule_matches

GLOBAL_CONFIG_ENV = "REPO_GUARD_GLOBAL_CONFIG"
REPO_CONFIG_NAME = ".repo-guard.toml"

_COMMON_KEYS = {"max_file_size_mb", "pdf_level", "rules", "allowlist"}
_GLOBAL_KEYS = _COMMON_KEYS | {"keywords"}


class ConfigError(Exception):
    """設定檔錯誤（結束碼 2）。訊息中不得出現關鍵字內容。"""


@dataclass(frozen=True)
class AllowEntry:
    path: str
    rule: str
    reason: str
    source: str  # 來源設定檔（顯示用）
    _path_regex: re.Pattern[str] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        # allowlist 會對每個 finding 比對；在載入設定時編譯一次即可。
        object.__setattr__(self, "_path_regex", glob_to_regex(self.path))

    def covers(self, path: str, rule: str) -> bool:
        return rule_matches(self.rule, rule) and self._path_regex.fullmatch(path) is not None


@dataclass
class Config:
    max_file_size_mb: float = DEFAULT_MAX_FILE_SIZE_MB
    pdf_level: str = "WARN"
    rules: dict[str, bool] = field(default_factory=dict)
    keywords: list[str] = field(default_factory=list)
    allowlist: list[AllowEntry] = field(default_factory=list)
    global_config_path: Path | None = None
    global_config_loaded: bool = False
    repo_config_path: Path | None = None
    repo_config_loaded: bool = False

    def rule_enabled(self, rule_id: str) -> bool:
        if rule_id in self.rules:
            return self.rules[rule_id]
        parent = rule_id.split("-")[0]
        if parent != rule_id and parent in self.rules:
            return self.rules[parent]
        rule = RULES.get(rule_id)
        return rule.default_enabled if rule else True

    def allowing(self, path: str, rule: str) -> AllowEntry | None:
        for entry in self.allowlist:
            if entry.covers(path, rule):
                return entry
        return None

    @property
    def max_file_size_bytes(self) -> int:
        return int(self.max_file_size_mb * 1024 * 1024)


# --- glob -------------------------------------------------------------------

def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """路徑 glob → regex。`*` 不跨目錄、`**` 可跨目錄；不含 `/` 的樣式比對任意層的檔名。"""
    pat = pattern.replace("\\", "/").lstrip("/")
    if "/" not in pat:
        pat = "**/" + pat
    out: list[str] = []
    i = 0
    while i < len(pat):
        c = pat[i]
        if pat.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
        elif pat.startswith("**", i):
            out.append(".*")
            i += 2
        elif c == "*":
            out.append("[^/]*")
            i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        elif c == "[":
            j = pat.find("]", i + 2)
            if j == -1:
                out.append(re.escape(c))
                i += 1
            else:
                body = pat[i + 1:j]
                if body.startswith("!"):
                    body = "^" + body[1:]
                out.append("[" + body.replace("\\", "\\\\") + "]")
                i = j + 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("".join(out))


def glob_match(pattern: str, path: str) -> bool:
    return glob_to_regex(pattern).fullmatch(path) is not None


# --- 載入 -------------------------------------------------------------------

def global_config_path() -> Path:
    env = os.environ.get(GLOBAL_CONFIG_ENV)
    if env:
        return Path(env)
    return Path.home() / ".repo-guard" / "config.toml"


def _read_toml(path: Path, label: str) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise ConfigError(f"{label}：無法讀取（{e.strerror or type(e).__name__}）") from None
    try:
        return tomllib.loads(raw.decode("utf-8-sig"))
    except UnicodeDecodeError:
        raise ConfigError(f"{label}：必須是 UTF-8 編碼") from None
    except tomllib.TOMLDecodeError as e:
        raise ConfigError(f"{label}：TOML 語法錯誤（{e}）") from None


def _validate(data: dict[str, Any], label: str, *, is_repo: bool) -> None:
    if is_repo and "keywords" in data:
        raise ConfigError(
            f"{label}：repo 設定檔不可包含 keywords 欄位（關鍵字清單只能放在全域設定 "
            f"~/.repo-guard/config.toml，避免被 commit 外洩）"
        )
    allowed = _COMMON_KEYS if is_repo else _GLOBAL_KEYS
    unknown = sorted(set(data) - allowed)
    if unknown:
        raise ConfigError(f"{label}：不認得的設定欄位：{', '.join(unknown)}")

    size = data.get("max_file_size_mb")
    if size is not None and (isinstance(size, bool) or not isinstance(size, (int, float)) or size <= 0):
        raise ConfigError(f"{label}：max_file_size_mb 必須是大於 0 的數字")
    level = data.get("pdf_level")
    if level is not None and level not in ("WARN", "BLOCK"):
        raise ConfigError(f"{label}：pdf_level 只能是 \"WARN\" 或 \"BLOCK\"")

    rules = data.get("rules", {})
    if not isinstance(rules, dict):
        raise ConfigError(f"{label}：[rules] 必須是資料表")
    for rid, val in rules.items():
        if rid not in CONFIG_RULE_IDS:
            raise ConfigError(f"{label}：[rules] 含未知規則 ID：{rid}")
        if not isinstance(val, bool):
            raise ConfigError(f"{label}：[rules] {rid} 必須是 true 或 false")

    kws = data.get("keywords")
    if kws is not None:
        if not isinstance(kws, list) or not all(isinstance(k, str) and k.strip() for k in kws):
            raise ConfigError(f"{label}：keywords 必須是非空字串的陣列")

    allow = data.get("allowlist", [])
    if not isinstance(allow, list) or not all(isinstance(a, dict) for a in allow):
        raise ConfigError(f"{label}：[[allowlist]] 必須是資料表陣列")
    for n, a in enumerate(allow, 1):
        extra = sorted(set(a) - {"path", "rule", "reason"})
        if extra:
            raise ConfigError(f"{label}：allowlist 第 {n} 筆含不認得的欄位：{', '.join(extra)}")
        for key in ("path", "rule", "reason"):
            v = a.get(key)
            if not isinstance(v, str) or not v.strip():
                hint = "（必須說明放行原因）" if key == "reason" else ""
                raise ConfigError(f"{label}：allowlist 第 {n} 筆缺少 {key}{hint}")
        if a["rule"] not in CONFIG_RULE_IDS:
            raise ConfigError(f"{label}：allowlist 第 {n} 筆的規則 ID 未知：{a['rule']}")


def _apply(cfg: Config, data: dict[str, Any], source: str) -> None:
    if "max_file_size_mb" in data:
        cfg.max_file_size_mb = float(data["max_file_size_mb"])
    if "pdf_level" in data:
        cfg.pdf_level = data["pdf_level"]
    cfg.rules.update(data.get("rules", {}))
    if "keywords" in data:
        cfg.keywords = [k.strip() for k in data["keywords"]]
    for a in data.get("allowlist", []):
        cfg.allowlist.append(AllowEntry(a["path"].strip(), a["rule"], a["reason"].strip(), source))


def load_config(repo_root: Path | None) -> Config:
    cfg = Config()
    gpath = global_config_path()
    cfg.global_config_path = gpath
    if gpath.is_file():
        label = f"全域設定 {gpath}"
        data = _read_toml(gpath, label)
        _validate(data, label, is_repo=False)
        _apply(cfg, data, "全域")
        cfg.global_config_loaded = True

    if repo_root is not None:
        rpath = repo_root / REPO_CONFIG_NAME
        cfg.repo_config_path = rpath
        if rpath.is_file():
            label = f"repo 設定 {REPO_CONFIG_NAME}"
            data = _read_toml(rpath, label)
            _validate(data, label, is_repo=True)
            _apply(cfg, data, "repo")
            cfg.repo_config_loaded = True
    return cfg


def describe(cfg: Config) -> dict[str, Any]:
    """`config --show` 用：合併後設定。關鍵字只回報數量。"""
    return {
        "global_config": {"path": str(cfg.global_config_path) if cfg.global_config_path else None,
                          "loaded": cfg.global_config_loaded},
        "repo_config": {"path": str(cfg.repo_config_path) if cfg.repo_config_path else None,
                        "loaded": cfg.repo_config_loaded},
        "max_file_size_mb": cfg.max_file_size_mb,
        "pdf_level": cfg.pdf_level,
        "rules": {rid: cfg.rule_enabled(rid) for rid in RULES if rid != "GITLEAKS"},
        "keywords_count": len(cfg.keywords),
        "allowlist": [{"path": a.path, "rule": a.rule, "reason": a.reason, "source": a.source}
                      for a in cfg.allowlist],
    }
