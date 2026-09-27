"""Type-check a small consumer against the published signatures.

The package ships ``py.typed`` from 0.2.0, so consumers now type-check against these
annotations. Callers naturally build ``choices`` as ``list[dict[str, Any]]``; ``list`` is
invariant, so a ``list[Mapping[...]]`` parameter rejected that. The parameters take
``Sequence[Mapping[str, Any]]`` instead.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

CONSUMER = textwrap.dedent(
    """
    from typing import Any

    from aais import create_request
    from aais.store import ApprovalAuthority, FileApprovalStore

    choices: list[dict[str, Any]] = [{"decision": "approve", "scope": "once"}]
    action: dict[str, Any] = {"kind": "shell.exec", "name": "echo", "summary": "echo ok"}
    origin: dict[str, Any] = {"harness": "example"}
    risk: dict[str, Any] = {"level": "low", "reasons": ["example"]}

    create_request(action=action, origin=origin, risk=risk, choices=choices, sequence=1)


    def add(authority: ApprovalAuthority, store: FileApprovalStore) -> None:
        authority.add_request(action=action, origin=origin, risk=risk, choices=choices)
        store.add_request(action=action, origin=origin, risk=risk, choices=choices)
    """
)


def test_consumer_with_list_of_dicts_type_checks(tmp_path: Path) -> None:
    api = pytest.importorskip("mypy.api")
    consumer = tmp_path / "consumer.py"
    consumer.write_text(CONSUMER, encoding="utf-8")
    stdout, stderr, status = api.run(
        [
            "--strict",
            "--no-incremental",
            "--config-file",
            str(ROOT / "pyproject.toml"),
            "--cache-dir",
            str(tmp_path / "cache"),
            str(consumer),
        ]
    )
    assert status == 0, stdout + stderr
