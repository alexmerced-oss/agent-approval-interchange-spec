"""The in-tree package version is consistent across metadata and code."""

from __future__ import annotations

import re
from importlib.metadata import version
from pathlib import Path

import aais

ROOT = Path(__file__).resolve().parents[1]


def test_version_matches_pyproject_metadata_and_changelog() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    match = re.search(r'^version = "([^"]+)"$', pyproject, re.MULTILINE)
    assert match is not None
    declared = match.group(1)
    assert aais.__version__ == declared
    assert version("agent-approval-interchange") == declared
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"Python library {declared}" in changelog or f"## {declared}" in changelog
