from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from repo_guard.cli import main

ZERO = "0" * 40


@pytest.fixture(autouse=True)
def isolated_env(tmp_path, monkeypatch):
    """不讀寫真正的 ~/.repo-guard 與全域 git config。"""
    monkeypatch.setenv("REPO_GUARD_GLOBAL_CONFIG", str(tmp_path / "global" / "config.toml"))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_AUTHOR_NAME", "t")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "t@example.com")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "t")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "t@example.com")


class Repo:
    def __init__(self, path: Path) -> None:
        self.path = path

    def git(self, *args: str) -> str:
        p = subprocess.run(["git", *args], cwd=self.path, capture_output=True, check=True)
        return p.stdout.decode("utf-8", "replace").strip()

    def write(self, rel: str, data: bytes | str = b"x") -> Path:
        p = self.path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode("utf-8") if isinstance(data, str) else data)
        return p

    def add(self, *rels: str) -> None:
        self.git("add", "--", *rels)

    def commit(self, msg: str = "c") -> str:
        self.git("commit", "-q", "-m", msg)
        return self.git("rev-parse", "HEAD")

    def run(self, *argv: str, stdin: bytes | None = None) -> int:
        import io
        return main(["-C", str(self.path), *argv], stdin=io.BytesIO(stdin) if stdin is not None else None)


@pytest.fixture
def repo(tmp_path) -> Repo:
    d = tmp_path / "work"
    d.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=d, check=True)
    return Repo(d)


@pytest.fixture
def global_cfg(tmp_path):
    def write(text: str) -> Path:
        p = tmp_path / "global" / "config.toml"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return p
    return write
