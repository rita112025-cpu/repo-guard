"""每條規則至少 1 個正例、1 個反例（單元層級，不需 git）。

測試用的「秘密」一律在執行時組字，避免本檔案自己被 repo-guard 掃到。
"""

from __future__ import annotations

import random

import pytest

from repo_guard.config import Config, glob_match
from repo_guard.rules import _TW_LETTER_CODE, tw_id_valid
from repo_guard.scanners import check_name, check_size, decode_text, mask_secret, mask_tw_id, scan_text


def make_tw_id(letter: str, gender: str, serial: str, *, valid: bool = True) -> str:
    """獨立於 rules.py 的實作：依戶政司規則算出檢查碼（或故意算錯）。"""
    code = _TW_LETTER_CODE[letter]
    digits = [code // 10, code % 10, int(gender), *map(int, serial)]
    weights = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1]
    s = sum(d * w for d, w in zip(digits, weights))
    check = (10 - s % 10) % 10
    if not valid:
        check = (check + 1) % 10
    return f"{letter}{gender}{serial}{check}"


def rules_of(findings):
    return [f.rule for f in findings]


def cfg(**kw) -> Config:
    c = Config()
    for k, v in kw.items():
        setattr(c, k, v)
    return c


# --- R1 ---
def test_r1_xlsx_chinese_name_blocks():
    f = check_name("報價/報價單_v2.xlsx", cfg())
    assert rules_of(f) == ["R1"] and f[0].level == "BLOCK"


def test_r1_uppercase_ext_and_no_stem():
    assert rules_of(check_name("a/B.XLSX", cfg())) == ["R1"]
    assert rules_of(check_name(".xlsx", cfg())) == ["R1"]


def test_r1_normal_file_ok():
    assert check_name("src/main.py", cfg()) == []


def test_r1_pdf_is_warn_by_default_and_configurable():
    assert check_name("a.pdf", cfg())[0].level == "WARN"
    assert check_name("a.pdf", cfg(pdf_level="BLOCK"))[0].level == "BLOCK"


def test_r1_can_be_disabled():
    assert check_name("a.xlsx", cfg(rules={"R1": False})) == []


# --- R2 ---
def test_r2_over_threshold_blocks():
    assert rules_of(check_size("a.txt", 6 * 1024 * 1024, cfg())) == ["R2"]


def test_r2_under_threshold_ok_and_configurable():
    assert check_size("a.txt", 4 * 1024 * 1024, cfg()) == []
    assert rules_of(check_size("a.txt", 2 * 1024 * 1024, cfg(max_file_size_mb=1))) == ["R2"]


# --- R3 ---
@pytest.mark.parametrize("name", [".env", ".env.local", "a/id_rsa", "x.pem", "k.KEY", "a.p12", "a.pfx",
                                  "credentials-prod.json", "service-account-x.json"])
def test_r3_positive(name):
    assert "R3" in rules_of(check_name(name, cfg()))


@pytest.mark.parametrize("name", [".env.example", "id_rsa.pub", "environment.py", "credentials.txt", "keyboard.py"])
def test_r3_negative(name):
    assert "R3" not in rules_of(check_name(name, cfg()))


# --- R4 ---
def _r4(text: str):
    return [f for f in scan_text("a.txt", text, cfg()) if f.rule == "R4"]


@pytest.mark.parametrize("secret", [
    "-----BEGIN " + "RSA PRIVATE KEY-----",
    "-----BEGIN " + "OPENSSH PRIVATE KEY-----",
    "AKIA" + "ABCDEFGHIJKLMNOP",
    "ghp_" + "a1B2c3D4" * 5,
    "github_pat_" + "A1b2C3d4E5" * 3,
    "hf_" + "aB3dE5gH7j" * 3 + "kL",
    "xoxb-" + "1234567890-abcdefghij",
    "xoxp-" + "1234567890-abcdefghij",
])
def test_r4_token_positive(secret):
    found = _r4(f"x = '{secret}'\n")
    assert found, secret
    assert secret not in found[0].snippet  # 已遮罩
    assert found[0].snippet == secret[:4] + "***"
    assert found[0].line == 1


@pytest.mark.parametrize("text", [
    "AKIA" + "SHORT",
    "ghp_short",
    "hf_something",
    "-----BEGIN " + "CERTIFICATE-----",
    "xoxz-" + "1234567890abcdef",
])
def test_r4_token_negative(text):
    assert _r4(text) == []


def test_r4_generic_assignment_positive():
    val = "Zq8" + "Xv2Lm9Pr4Tt7Uw1"
    for line in (f'password = "{val}"', f"API_KEY: {val}", f"db_secret='{val}'", f'"token": "{val}"'):
        found = _r4(line)
        assert found, line
        assert val not in found[0].snippet and found[0].snippet == val[:4] + "***"


@pytest.mark.parametrize("line", [
    'password = "short"',                                   # < 16
    "password = os.environ.get('DB_PASSWORD')",             # 變數引用
    "token: ${{ secrets.GITHUB_TOKEN }}",                   # CI 引用
    "secret = some_long_identifier_name",                   # 識別字
    'api_key = "your-api-key-goes-here"',                   # 佔位
    "SECRET = SOME_LONG_CONSTANT_NAME",
    "password = self.settings.PASSWORD_HASHER",
])
def test_r4_generic_assignment_negative(line):
    assert _r4(line) == []


# --- R5 ---
def test_r5_id_checksum_algorithm_matches_independent_impl():
    rnd = random.Random(1)
    for _ in range(300):
        letter = rnd.choice(list(_TW_LETTER_CODE))
        serial = "".join(rnd.choice("0123456789") for _ in range(7))
        good = make_tw_id(letter, rnd.choice("12"), serial)
        assert tw_id_valid(good)
        bad = good[:-1] + str((int(good[-1]) + 1) % 10)
        assert not tw_id_valid(bad)


def test_r5_id_positive_and_masked():
    vid = make_tw_id("F", "1", "2345678")
    found = [f for f in scan_text("a.txt", f"客戶身分證：{vid}\n", cfg()) if f.rule == "R5-ID"]
    assert len(found) == 1 and found[0].level == "BLOCK"
    assert found[0].snippet == mask_tw_id(vid) == vid[0] + "******" + vid[-2:]
    assert vid not in found[0].snippet


def test_r5_id_negative_invalid_checksum_or_embedded():
    bad = make_tw_id("F", "1", "2345678", valid=False)
    vid = make_tw_id("F", "1", "2345678")
    assert scan_text("a.txt", bad, cfg()) == []
    assert scan_text("a.txt", f"x{vid}", cfg()) == []          # 前面緊接字母/數字
    assert scan_text("a.txt", vid + "0", cfg()) == []          # 後面多一碼


def test_r5_phone_warn():
    f = [x for x in scan_text("a.txt", "電話 0912-345-678", cfg()) if x.rule == "R5-PHONE"]
    assert len(f) == 1 and f[0].level == "WARN"
    f2 = [x for x in scan_text("a.txt", "0912345678", cfg()) if x.rule == "R5-PHONE"]
    assert len(f2) == 1


def test_r5_phone_negative():
    assert scan_text("a.txt", "02-2345-6789 / 09123456789 / 0812345678", cfg()) == []


def test_r5_email_off_by_default_on_when_enabled():
    text = "contact: someone@example.com"
    assert scan_text("a.txt", text, cfg()) == []
    f = scan_text("a.txt", text, cfg(rules={"R5-EMAIL": True}))
    assert rules_of(f) == ["R5-EMAIL"] and "someone@example.com" not in f[0].snippet


def test_r5_parent_switch_disables_children():
    vid = make_tw_id("A", "2", "1234567")
    assert scan_text("a.txt", vid + " 0912345678", cfg(rules={"R5": False})) == []


# --- R6 ---
def test_r6_keyword_case_insensitive_and_masked():
    c = cfg(keywords=["客戶甲公司", "Alpha Project"])
    f = scan_text("a.txt", "x\n這是 ALPHA project 的資料\n", c)
    assert rules_of(f) == ["R6"] and f[0].line == 2
    assert f[0].snippet == "[關鍵字 #2]"
    assert "Alpha" not in (f[0].snippet + f[0].message)


def test_r6_no_keywords_or_no_match():
    assert scan_text("a.txt", "Alpha Project", cfg()) == []
    assert scan_text("a.txt", "nothing here", cfg(keywords=["Alpha Project"])) == []


def test_r6_cfg_warn_for_keyword_config_in_repo():
    f = scan_text(".repo-guard/config.toml", 'keywords = ["a"]\n', cfg())
    assert rules_of(f) == ["R6-CFG"]
    assert scan_text("config.toml", 'keywords = ["a"]\n', cfg()) == []


# --- 編碼 / glob / 遮罩 ---
def test_decode_variants():
    assert decode_text("你好".encode("utf-8"))[0] == "你好"
    assert decode_text(b"\xef\xbb\xbf" + "你好".encode("utf-8"))[0] == "你好"
    assert decode_text("你好".encode("cp950"))[0] == "你好"
    assert decode_text("你好".encode("utf-16"))[0] == "你好"
    assert decode_text(b"abc\x00def")[0] is None
    assert decode_text(b"abc\xff\xff\xffdef")[0] is None


def test_glob():
    assert glob_match("tests/fixtures/*.xlsx", "tests/fixtures/報價.xlsx")
    assert not glob_match("tests/fixtures/*.xlsx", "tests/fixtures/sub/a.xlsx")
    assert glob_match("tests/**/*.xlsx", "tests/fixtures/sub/a.xlsx")
    assert glob_match("*.xlsx", "a/b/c.xlsx")
    assert not glob_match("*.xlsx", "a/b/c.xls")


def test_mask_secret():
    assert mask_secret("abcdefghijklmnop") == "abcd***"
