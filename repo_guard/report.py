"""輸出（text / json / markdown，繁體中文）。輸出只使用遮罩後的片段；路徑中的關鍵字也會遮罩。"""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from . import __version__
from .rules import RULES
from .scanners import Finding, ScanResult, Sanitizer

MODE_LABEL = {
    "staged": "--staged（已暫存變更）",
    "pre-push": "--pre-push（未推送的 commit）",
    "all": "--all（工作目錄全部檔案）",
    "history": "--history（所有歷史 commit）",
    "history-names": "--history --names-only（歷史檔名）",
}


def suggestions(f: Finding, mode: str, san: Sanitizer, no_head: bool = False) -> list[str]:
    path = san.clean(f.path)
    out: list[str] = []
    if mode == "staged" and no_head:
        out.append(f'取消暫存（尚無任何 commit，不能用 restore；不會動到檔案本身）：git rm --cached -- "{path}"')
    elif mode == "staged":
        out.append(f'取消暫存（不會動到檔案本身）：git restore --staged -- "{path}"')
    elif mode == "all":
        out.append(f'若此檔案已被追蹤，可自行評估後執行（保留本機檔案）：git rm --cached -- "{path}"')
    else:
        out.append(
            f"此檔案已在 commit {f.ref or '?'} 中；移除需改寫歷史（例如 git rebase -i 或 git filter-repo），"
            "本工具不會代為執行。若該 commit 已推送，請視為已外洩。"
        )

    if f.rule in ("R1", "R2", "R3"):
        out.append(f'不想再被追蹤：在 .gitignore 加入一行：{path}')
    elif f.rule in ("R4", "R5-ID", "R5-PHONE", "R5-EMAIL", "R6"):
        out.append("移除該內容，改用環境變數或不入版控的設定檔；若為真的秘密，請同時到來源服務撤銷並更換。")
    elif f.rule == "R6-CFG":
        out.append("把關鍵字清單移到 ~/.repo-guard/config.toml，或將該檔案加入 .gitignore。")

    if f.rule in RULES and f.rule not in ("R6-CFG", "GITLEAKS"):
        rid = f.rule
        out.append(
            f'確認為誤報／可放行：在 .repo-guard.toml 加入 [[allowlist]]，'
            f'path = "{path}"、rule = "{rid}"、reason = "<必填：放行原因>"'
        )
    return out


def _summary(res: ScanResult, san: Sanitizer) -> dict[str, Any]:
    reasons = Counter(why for _, why in res.skipped)
    return {
        "mode": res.mode,
        "scanned_files": res.scanned,
        "skipped_files": len(res.skipped),
        "skipped_reasons": dict(reasons),
        "block": res.block_count,
        "warn": res.warn_count,
        "allowlisted": len(res.allowlisted),
        "omitted": sum(res.omitted.values()),
        "result": "BLOCK" if res.block_count else "PASS",
    }


def _finding_dict(f: Finding, mode: str, san: Sanitizer, no_head: bool = False) -> dict[str, Any]:
    return {
        "rule": f.rule,
        "level": f.level,
        "title": RULES[f.rule].title if f.rule in RULES else f.rule,
        "path": san.clean(f.path),
        "line": f.line,
        "commit": f.ref,
        "snippet": f.snippet,
        "message": san.clean(f.message),
        "suggestions": suggestions(f, mode, san, no_head),
    }


def to_dict(res: ScanResult, san: Sanitizer) -> dict[str, Any]:
    return {
        "tool": "repo-guard",
        "version": __version__,
        "summary": _summary(res, san),
        "findings": [_finding_dict(f, res.mode, san, res.no_head) for f in res.findings],
        "allowlisted": [
            {"rule": f.rule, "path": san.clean(f.path), "line": f.line, "reason": san.clean(why)}
            for f, why in res.allowlisted
        ],
        "skipped": [{"path": san.clean(p), "reason": why} for p, why in res.skipped],
        "notes": [san.clean(n) for n in res.notes],
    }


def _where(d: dict[str, Any]) -> str:
    s = d["path"]
    if d["line"]:
        s += f":{d['line']}"
    if d["commit"]:
        s += f"（commit {d['commit']}）"
    return s


def render_text(res: ScanResult, san: Sanitizer) -> str:
    d = to_dict(res, san)
    s = d["summary"]
    lines = [f"repo-guard 掃描結果　模式：{MODE_LABEL.get(res.mode, res.mode)}", "=" * 60]
    for fd in d["findings"]:
        lines.append(f"[{fd['level']}] {fd['rule']} {fd['title']}")
        lines.append(f"  檔案：{_where(fd)}")
        lines.append(f"  說明：{fd['message']}")
        if fd["snippet"]:
            lines.append(f"  片段：{fd['snippet']}")
        for i, sg in enumerate(fd["suggestions"], 1):
            lines.append(f"  建議{i}：{sg}")
        lines.append("")
    if res.omitted:
        lines.append(f"（另有 {sum(res.omitted.values())} 筆同檔同規則的結果未逐筆列出，已計入摘要）")
        lines.append("")
    for n in d["notes"]:
        lines.append(f"注意：{n}")
    lines += ["-" * 60, "摘要",
              f"  掃描檔案數：{s['scanned_files']}",
              f"  跳過檔案數：{s['skipped_files']}"
              + (f"（{'、'.join(f'{k} ×{v}' for k, v in s['skipped_reasons'].items())}）" if s["skipped_reasons"] else ""),
              f"  BLOCK：{s['block']}　WARN：{s['warn']}"
              + (f"　（allowlist 放行 {s['allowlisted']} 筆）" if s["allowlisted"] else ""),
              "結果：" + ("有 BLOCK，已阻擋" if s["block"] else "通過（無 BLOCK）")]
    if d["skipped"]:
        lines.append("  跳過明細（僅略過內容掃描，檔名規則仍有檢查）：")
        for sk in d["skipped"][:10]:
            lines.append(f"    - {sk['path']}：{sk['reason']}")
        if len(d["skipped"]) > 10:
            lines.append(f"    …另有 {len(d['skipped']) - 10} 筆（完整清單請用 --format json）")
    return "\n".join(lines) + "\n"


def render_json(res: ScanResult, san: Sanitizer) -> str:
    return json.dumps(to_dict(res, san), ensure_ascii=False, indent=2) + "\n"


def _md_cell(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_markdown(res: ScanResult, san: Sanitizer) -> str:
    d = to_dict(res, san)
    s = d["summary"]
    out = [f"# repo-guard 掃描報告", "", f"- 模式：{MODE_LABEL.get(res.mode, res.mode)}",
           f"- 結果：**{'有 BLOCK，已阻擋' if s['block'] else '通過（無 BLOCK）'}**", ""]
    out += ["## 摘要", "", "| 項目 | 數量 |", "|---|---|",
            f"| 掃描檔案數 | {s['scanned_files']} |",
            f"| 跳過檔案數 | {s['skipped_files']} |",
            f"| BLOCK | {s['block']} |", f"| WARN | {s['warn']} |",
            f"| allowlist 放行 | {s['allowlisted']} |", ""]
    if s["skipped_reasons"]:
        out += ["跳過原因：" + "、".join(f"{k} ×{v}" for k, v in s["skipped_reasons"].items()), ""]
    if d["findings"]:
        out += ["## 結果", ""]
        for fd in d["findings"]:
            out.append(f"### [{fd['level']}] {fd['rule']} {_md_cell(fd['title'])}")
            out.append("")
            out.append(f"- 檔案：`{_where(fd)}`")
            out.append(f"- 說明：{_md_cell(fd['message'])}")
            if fd["snippet"]:
                out.append(f"- 片段：`{fd['snippet']}`")
            out.append("- 建議：")
            for sg in fd["suggestions"]:
                out.append(f"  - {sg}")
            out.append("")
    if res.omitted:
        out += [f"另有 {sum(res.omitted.values())} 筆同檔同規則的結果未逐筆列出，已計入摘要。", ""]
    for n in d["notes"]:
        out.append(f"> 注意：{n}")
    return "\n".join(out) + "\n"


RENDERERS = {"text": render_text, "json": render_json, "markdown": render_markdown}


def render_config(desc: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(desc, ensure_ascii=False, indent=2) + "\n"
    g, r = desc["global_config"], desc["repo_config"]
    lines = [
        "repo-guard 合併後設定（優先序：repo > 全域 > 預設）",
        f"  全域設定：{g['path']}（{'已載入' if g['loaded'] else '不存在，使用預設'}）",
        f"  repo 設定：{r['path'] or '（不在 repo 內）'}（{'已載入' if r['loaded'] else '不存在，使用預設'}）",
        f"  檔案大小門檻：{desc['max_file_size_mb']:g} MB",
        f"  .pdf 等級：{desc['pdf_level']}",
        f"  自訂關鍵字：{desc['keywords_count']} 個（內容不顯示）",
        "  規則開關：",
    ]
    for rid, on in desc["rules"].items():
        lines.append(f"    {rid}: {'開' if on else '關'}")
    lines.append(f"  allowlist：{len(desc['allowlist'])} 筆")
    for a in desc["allowlist"]:
        lines.append(f"    - {a['path']}  {a['rule']}  原因：{a['reason']}  （{a['source']}）")
    return "\n".join(lines) + "\n"
