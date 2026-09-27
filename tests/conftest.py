from __future__ import annotations

import os
import shutil
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

import pytest


@pytest.fixture
def store_dir(tmp_path: Path) -> Iterator[Path]:
    """A directory for store files, on tmpfs when the platform offers one.

    Contention tests perform hundreds of fsyncs; on a busy disk each can take a
    large fraction of a second. Locking semantics are identical on tmpfs, and
    ``test_store_multiprocess.py`` keeps one small test on the real disk.
    """

    shm = Path("/dev/shm")
    if sys.platform.startswith("linux") and shm.is_dir() and os.access(shm, os.W_OK):
        directory = Path(tempfile.mkdtemp(prefix="aais-store-", dir=shm))
        try:
            yield directory
        finally:
            shutil.rmtree(directory, ignore_errors=True)
    else:
        yield tmp_path
