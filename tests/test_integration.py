"""整合測試：tmp 目錄 git init，實際呼叫 CLI。"""

from __future__ import annotations

import json
import os
import subprocess
import sys

from conftest import ZERO
from test_rules import make_tw_id

ALLOW = '[[allowlist]]\npath = "報價單_v2.xlsx"\nrule = "R1"\nreason = "測試用假資料"\n'


# 1. staged「報價單_v2.xlsx」→ exit 1；2. allowlist → exit 0；3. 缺原因 → exit 2
def test_staged_xlsx_blocks(repo, capsys):
    repo.write("報價單_v2.xlsx", b"PK\x03\x04")
    repo.add("報價單_v2.xlsx")
    assert repo.run("scan", "--staged") == 1
    out = capsys.readouterr().out
    assert "R1" in out and "報價單_v2.xlsx" in out and "git rm --cached" in out and "git restore --staged" not in out
    assert "BLOCK：1" in out


def test_allowlist_makes_it_pass(repo, capsys):
    repo.write("報價單_v2.xlsx", b"PK\x03\x04")
    repo.write(".repo-guard.toml", ALLOW)
    repo.add("報價單_v2.xlsx")
    assert repo.run("scan", "--staged") == 0
    assert "allowlist 放行 1 筆" in capsys.readouterr().out


def test_allowlist_without_reason_is_config_error(repo, capsys):
    repo.write("報價單_v2.xlsx", b"x")
    repo.write(".repo-guard.toml", '[[allowlist]]\npath = "報價單_v2.xlsx"\nrule = "R1"\n')
    repo.add("報價單_v2.xlsx")
    assert repo.run("scan", "--staged") == 2
    assert "reason" in capsys.readouterr().err


def test_allowlist_empty_reason_is_config_error(repo):
    repo.write(".repo-guard.toml", '[[allowlist]]\npath = "a"\nrule = "R1"\nreason = "  "\n')
    assert repo.run("scan", "--all") == 2


def test_repo_config_with_keywords_is_error(repo, capsys):
    repo.write(".repo-guard.toml", 'keywords = ["secretcustomer"]\n')
    assert repo.run("scan", "--all") == 2
    err = capsys.readouterr().err
    assert "keywords" in err and "secretcustomer" not in err


def test_allowlist_glob_and_fixture_example(repo):
    repo.write("tests/fixtures/a.xlsx", b"x")
    repo.write(".repo-guard.toml",
               '[[allowlist]]\npath = "tests/fixtures/*.xlsx"\nrule = "R1"\nreason = "測試用假資料"\n')
    repo.add("tests/fixtures/a.xlsx")
    assert repo.run("scan", "--staged") == 0


def test_clean_staged_passes_and_reads_index_not_worktree(repo, capsys):
    secret = "ghp_" + "a1B2c3D4" * 5
    repo.write("a.py", "print(1)\n")
    repo.add("a.py")
    repo.write("a.py", f"t = '{secret}'\n")  # 工作目錄有秘密，但沒 stage
    assert repo.run("scan", "--staged") == 0
    capsys.readouterr()
    repo.add("a.py")
    assert repo.run("scan", "--staged") == 1


# 4. pre-push 新分支：只掃未推送的 commits
def test_pre_push_new_branch_scans_only_unpushed(repo, capsys):
    repo.write("old_remote.csv", b"a,b")
    repo.add("old_remote.csv")
    c1 = repo.commit("already on remote")
    repo.git("update-ref", "refs/remotes/origin/main", c1)  # 模擬遠端追蹤，不實際連線
    repo.git("checkout", "-q", "-b", "feature")
    repo.write("報價單_v2.xlsx", b"x")
    repo.add("報價單_v2.xlsx")
    c2 = repo.commit("new")
    stdin = f"refs/heads/feature {c2} refs/heads/feature {ZERO}\n".encode()
    assert repo.run("scan", "--pre-push", "origin", "https://example.invalid/x.git", stdin=stdin) == 1
    out = capsys.readouterr().out
    assert "報價單_v2.xlsx" in out and "old_remote.csv" not in out
    assert f"commit {c2[:8]}" in out


def test_pre_push_delete_branch_skipped_and_existing_branch_range(repo, capsys):
    repo.write("a.txt", "ok")
    repo.add("a.txt")
    c1 = repo.commit("1")
    repo.write("b.xlsx", b"x")
    repo.add("b.xlsx")
    c2 = repo.commit("2")
    assert repo.run("scan", "--pre-push", "origin", "u", stdin=f"(delete) {ZERO} refs/heads/x {c1}\n".encode()) == 0
    assert "刪除分支" in capsys.readouterr().out
    assert repo.run("scan", "--pre-push", "origin", "u",
                    stdin=f"refs/heads/main {c2} refs/heads/main {c1}\n".encode()) == 1
    assert repo.run("scan", "--pre-push", "origin", "u",
                    stdin=f"refs/heads/main {c1} refs/heads/main {c1}\n".encode()) == 0


# 5. 已存在非本工具 hook 時不覆寫；6. uninstall 不刪非本工具 hook
def test_install_hooks_does_not_overwrite_foreign_hook(repo, capsys):
    hooks = repo.path / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "pre-commit").write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    rc = repo.run("install-hooks")
    assert rc == 2
    assert (hooks / "pre-commit").read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"
    assert "手動" in capsys.readouterr().out
    assert "repo-guard-managed-hook" in (hooks / "pre-push").read_text(encoding="utf-8")  # 另一個仍安裝


def test_install_force_backs_up_then_writes(repo):
    hooks = repo.path / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "pre-push").write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    assert repo.run("install-hooks", "--force") == 0
    baks = list(hooks.glob("pre-push.bak-*"))
    assert len(baks) == 1 and baks[0].read_text(encoding="utf-8") == "#!/bin/sh\necho mine\n"
    assert "repo-guard-managed-hook" in (hooks / "pre-push").read_text(encoding="utf-8")


def test_uninstall_only_removes_own_hooks(repo):
    hooks = repo.path / ".git" / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "pre-commit").write_text("#!/bin/sh\necho mine\n", encoding="utf-8")
    repo.run("install-hooks")  # pre-push 被安裝，pre-commit 被略過
    assert repo.run("uninstall-hooks") == 0
    assert (hooks / "pre-commit").exists()
    assert not (hooks / "pre-push").exists()


def test_install_hooks_respects_core_hooks_path(repo):
    custom = repo.path / "my-hooks"
    repo.git("config", "core.hooksPath", "my-hooks")
    assert repo.run("install-hooks") == 0
    assert (custom / "pre-commit").exists() and (custom / "pre-push").exists()
    assert not (repo.path / ".git" / "hooks" / "pre-commit").exists()


def test_hook_end_to_end_blocks_real_commit(repo):
    """實際讓 git 執行 hook：有 .xlsx 的 commit 失敗，乾淨的 commit 成功。"""
    assert repo.run("install-hooks") == 0
    env = dict(os.environ)
    py_dir = os.path.dirname(sys.executable)
    env["PATH"] = py_dir + os.pathsep + env["PATH"]
    repo.write("a.xlsx", b"x")
    repo.add("a.xlsx")
    bad = subprocess.run(["git", "commit", "-q", "-m", "x"], cwd=repo.path, env=env, capture_output=True)
    assert bad.returncode != 0
    repo.git("rm", "-q", "--cached", "a.xlsx")  # 僅限測試自己的 tmp repo
    repo.write("ok.txt", "hello")
    repo.add("ok.txt")
    good = subprocess.run(["git", "commit", "-q", "-m", "x"], cwd=repo.path, env=env, capture_output=True)
    assert good.returncode == 0, good.stderr


# --scan --all / --history
def test_all_skips_gitignored_and_scans_untracked(repo, capsys):
    repo.write(".gitignore", "ignored.csv\n")
    repo.write("ignored.csv", b"x")
    repo.write("new.csv", b"x")
    assert repo.run("scan", "--all") == 1
    out = capsys.readouterr().out
    assert "new.csv" in out and "ignored.csv" not in out


def test_history_finds_removed_file_and_names_only(repo, capsys):
    secret = "ghp_" + "a1B2c3D4" * 5
    repo.write("a.csv", b"x")
    repo.write("s.txt", f"t='{secret}'\n")
    repo.add("a.csv", "s.txt")
    repo.commit("add")
    repo.git("rm", "-q", "a.csv", "s.txt")
    repo.commit("remove")
    assert repo.run("scan", "--history") == 1
    out = capsys.readouterr().out
    assert "a.csv" in out and "s.txt" in out and "R4" in out
    assert repo.run("scan", "--history", "--names-only", "--format", "json") == 1
    d = json.loads(capsys.readouterr().out)
    assert {f["rule"] for f in d["findings"]} == {"R1"}


def test_names_only_requires_history(repo):
    assert repo.run("scan", "--all", "--names-only") == 2


def test_not_a_git_repo_is_error(tmp_path, capsys):
    from repo_guard.cli import main
    d = tmp_path / "plain"
    d.mkdir()
    assert main(["-C", str(d), "scan", "--staged"]) == 2


def test_large_file_blocks_r2(repo):
    repo.write("big.txt", b"a" * (6 * 1024 * 1024))
    repo.add("big.txt")
    assert repo.run("scan", "--staged") == 1


def test_global_config_keywords_and_config_show(repo, global_cfg, capsys):
    global_cfg('keywords = ["客戶甲公司", "Beta案"]\nmax_file_size_mb = 3\n')
    repo.write("n.txt", "這是客戶甲公司的報價\n")
    repo.add("n.txt")
    assert repo.run("scan", "--staged") == 1
    capsys.readouterr()
    assert repo.run("config", "--show") == 0
    out = capsys.readouterr().out
    assert "自訂關鍵字：2 個" in out and "客戶甲公司" not in out and "Beta案" not in out
    assert "3 MB" in out


def test_r6_cfg_warn_when_global_config_inside_repo(repo, tmp_path, monkeypatch, capsys):
    cfgp = repo.path / ".repo-guard" / "config.toml"
    cfgp.parent.mkdir()
    cfgp.write_text('keywords = ["zzkw"]\n', encoding="utf-8")
    monkeypatch.setenv("REPO_GUARD_GLOBAL_CONFIG", str(cfgp))
    # 設定檔本身含關鍵字 → R6 BLOCK，同時恰好一筆 R6-CFG WARN（不重複）
    assert repo.run("scan", "--all") == 1
    assert capsys.readouterr().out.count("R6-CFG") == 1
    repo.write(".gitignore", ".repo-guard/\n")
    assert repo.run("scan", "--all") == 0
    assert "R6-CFG" not in capsys.readouterr().out


def test_with_gitleaks_missing_shows_notice(repo, monkeypatch, capsys):
    monkeypatch.setattr("shutil.which", lambda name: None)
    repo.write("a.txt", "ok")
    assert repo.run("scan", "--all", "--with-gitleaks") == 0
    assert "未安裝 gitleaks" in capsys.readouterr().out


# --- 編碼 -------------------------------------------------------------------

def test_encodings_do_not_crash(repo, global_cfg, capsys):
    global_cfg('keywords = ["客戶甲公司"]\n')
    repo.write("bom.txt", b"\xef\xbb\xbf" + "客戶甲公司\n".encode("utf-8"))
    repo.write("big5.txt", "客戶甲公司的案子\n".encode("cp950"))
    repo.write("bin.dat", b"\x00\x01\x02" + "客戶甲公司".encode("utf-8"))
    repo.write("junk.txt", b"abc\xff\xff\xffdef")
    repo.write("u16.txt", "客戶甲公司\n".encode("utf-16"))
    assert repo.run("scan", "--all", "--format", "json") == 1
    d = json.loads(capsys.readouterr().out)
    hit = {f["path"] for f in d["findings"] if f["rule"] == "R6"}
    assert hit == {"bom.txt", "big5.txt", "u16.txt"}
    skipped = {s["path"]: s["reason"] for s in d["skipped"]}
    assert set(skipped) == {"bin.dat", "junk.txt"}
    assert d["summary"]["skipped_files"] == 2


# --- 遮罩：三種格式 + --report 都不得出現原文 ----------------------------------

def test_no_secret_or_keyword_leaks_in_any_format(repo, global_cfg, tmp_path, capsys):
    secret = "ghp_" + "Zx9Yw8Vu7T" * 4
    aws = "AKIA" + "QWERTYUIOPASDFGH"
    pw = "Pq4" + "Rs7Tu1Vw3Xy5Zz"
    vid = make_tw_id("B", "2", "7654321")
    keyword = "神秘客戶乙"
    global_cfg(f'keywords = ["{keyword}", "Gamma-Project"]\n')
    repo.write("data.txt", f"a={secret}\nb={aws}\npassword = \"{pw}\"\nid {vid}\n{keyword} and GAMMA-project\n")
    repo.write(f"{keyword}_報價.xlsx", b"x")  # 檔名也含關鍵字
    repo.add("data.txt", f"{keyword}_報價.xlsx")
    forbidden = [secret, aws, pw, vid, keyword, "Gamma-Project", "GAMMA-project"]
    for fmt in ("text", "json", "markdown"):
        report = tmp_path / f"r.{fmt}"
        assert repo.run("scan", "--staged", "--format", fmt, "--report", str(report)) == 1
        captured = capsys.readouterr()
        for blob in (captured.out, captured.err, report.read_text(encoding="utf-8")):
            for bad in forbidden:
                assert bad not in blob, (fmt, bad)
        assert "[關鍵字 #1]" in captured.out and "[關鍵字 #2]" in captured.out
        assert vid[0] + "******" + vid[-2:] in captured.out
        assert secret[:4] + "***" in captured.out
    repo.run("config", "--show")
    assert keyword not in capsys.readouterr().out


def test_findings_capped_per_file_rule(repo, capsys):
    lines = "\n".join("0912345%03d" % i for i in range(60))
    repo.write("phones.txt", lines)
    repo.add("phones.txt")
    assert repo.run("scan", "--staged", "--format", "json") == 0
    d = json.loads(capsys.readouterr().out)
    assert len(d["findings"]) == 20 and d["summary"]["warn"] == 60


# --- gitleaks 版本偵測：新版用 git / dir，< 8.19 用 protect / detect ---
def test_gitleaks_cmd_by_version(tmp_path):
    from repo_guard.cli import _gitleaks_cmd
    c = ["--redact"]
    new = (8, 30, 0)
    assert _gitleaks_cmd("gl", "staged", tmp_path, c, new)[1:3] == ["git", "--staged"]
    assert _gitleaks_cmd("gl", "all", tmp_path, c, new)[1] == "dir"
    assert _gitleaks_cmd("gl", "history", tmp_path, c, new)[1] == "git"
    old = (8, 18, 4)
    assert _gitleaks_cmd("gl", "staged", tmp_path, c, old)[1:3] == ["protect", "--staged"]
    assert _gitleaks_cmd("gl", "all", tmp_path, c, old)[1:3] == ["detect", "--no-git"]
    assert _gitleaks_cmd("gl", "history", tmp_path, c, old)[1] == "detect"
    assert _gitleaks_cmd("gl", "staged", tmp_path, c, None)[1] == "git"  # 版本未知視為新版


def test_gitleaks_version_parse(monkeypatch):
    from repo_guard import cli

    class P:
        stdout = b"v8.18.4\n"
    monkeypatch.setattr(cli.subprocess, "run", lambda *a, **k: P())
    assert cli._gitleaks_version("gl") == (8, 18, 4)
    P.stdout = b"garbage"
    assert cli._gitleaks_version("gl") is None


def test_staged_suggestion_restore_when_head_exists(repo, capsys):
    repo.write("a.txt", "a")
    repo.add("a.txt")
    repo.commit()
    repo.write("報價單_v2.xlsx", b"PK")
    repo.add("報價單_v2.xlsx")
    assert repo.run("scan", "--staged") == 1
    out = capsys.readouterr().out
    assert "git restore --staged" in out and "git rm --cached" not in out
