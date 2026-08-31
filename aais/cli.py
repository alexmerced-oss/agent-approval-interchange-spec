"""AAIS validation command."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import ValidationError, validate


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate an AAIS 1.0 JSON envelope")
    parser.add_argument("document", type=Path)
    args = parser.parse_args()
    try:
        validate(json.loads(args.document.read_text(encoding="utf-8")))
    except (OSError, json.JSONDecodeError, ValidationError) as exc:
        parser.exit(1, f"invalid: {exc}\n")
    print("valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
