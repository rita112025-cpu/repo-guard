"""install-hooks / uninstall-hooks。只管理含識別標記的 hook，不覆寫他人的 hook。"""

from __future__ import annotations

import shlex
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

MARKER = "# repo-guard-managed-hook v1"
HOOK_NAMES = ("pre-commit", "pre-push")


def _script(name: str) -> str:
    py = shlex.quote(Path(sys.executable).as_posix())
    args = "scan --staged" if name == "pre-commit" else 'scan --pre-push "$@"'
    return f"""#!/bin/sh
{MARKER}
# 由 repo-guard install-hooks 產生。移除請用：repo-guard uninstall-hooks
if command -v repo-guard >/dev/null 2>&1; then
  repo-guard {args}
  exit $?
fi
if [ -x {py} ]; then
  {py} -m repo_guard {args}
  exit $?
fi
echo "repo-guard: 找不到 repo-guard 指令，本次檢查未執行（請確認已安裝並在 PATH 中）" >&2
exit 0
"""


def is_ours(path: Path) -> bool:
    try:
        return MARKER in path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False


@dataclass
class HookOutcome:
    name: str
    status: str  # installed | updated | skipped | backed-up | removed | not-ours | absent
    detail: str = ""


def manual_merge_help(name: str) -> str:
    args = "scan --staged" if name == "pre-commit" else 'scan --pre-push "$@"'
    return (
        f"已有非 repo-guard 的 {name} hook，未覆寫。請手動在該檔案中加入下列指令"
        f"（pre-push 需保留 stdin 與參數）：\n    repo-guard {args} || exit $?\n"
        f"或改用 --force（會先備份為 {name}.bak-<時間>，再寫入本工具的 hook）。"
    )


def install(hooks: Path, *, force: bool) -> list[HookOutcome]:
    hooks.mkdir(parents=True, exist_ok=True)
    results: list[HookOutcome] = []
    for name in HOOK_NAMES:
        target = hooks / name
        backup_note = ""
        status = "installed"
        if target.exists():
            if is_ours(target):
                status = "updated"
            elif not force:
                results.append(HookOutcome(name, "skipped", manual_merge_help(name)))
                continue
            else:
                stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
                bak = hooks / f"{name}.bak-{stamp}"
                n = 1
                while bak.exists():
                    n += 1
                    bak = hooks / f"{name}.bak-{stamp}-{n}"
                shutil.copy2(target, bak)
                backup_note = f"原 hook 已備份為 {bak.name}"
                status = "backed-up"
        with open(target, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(_script(name))
        try:
            target.chmod(0o755)
        except OSError:
            pass
        results.append(HookOutcome(name, status, backup_note))
    return results


def uninstall(hooks: Path) -> list[HookOutcome]:
    results: list[HookOutcome] = []
    for name in HOOK_NAMES:
        target = hooks / name
        if not target.exists():
            results.append(HookOutcome(name, "absent"))
        elif is_ours(target):
            target.unlink()
            results.append(HookOutcome(name, "removed"))
        else:
            results.append(HookOutcome(name, "not-ours", "非 repo-guard 的 hook，未移除"))
    return results
