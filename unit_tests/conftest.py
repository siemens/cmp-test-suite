# SPDX-FileCopyrightText: Copyright 2026 Siemens AG
#
# SPDX-License-Identifier: Apache-2.0

"""Session-wide setup shared by all unit tests.

Several tests lazily (re)generate certificate/key fixtures under `data/unittest/`,
`data/trustanchors/`, `data/mock_ca/`, and `data/trusted_ras/` via
`unit_tests.utils_for_test.load_or_generate_cert_chain()`. That function uses a plain
`if not os.path.isfile(...): generate()` check with non-atomic writes and no locking,
which is a race when tests run in parallel (e.g. `pytest -n auto`): two workers can
regenerate the same shared files at the same time, and a third worker can read a
half-written or inconsistent file in between.

This fixture generates those fixtures exactly once, before any test runs, regardless of
how many `pytest-xdist` worker processes are used -- this is the pytest equivalent of a
Robot Framework "Suite Setup". It intentionally does NOT rely on the `filelock` package;
`os.O_CREAT | os.O_EXCL` is atomic on POSIX and is enough for this one-shot use case.
"""

import os
import time

import pytest


@pytest.fixture(scope="session", autouse=True)
def _generate_shared_test_fixtures(tmp_path_factory, worker_id):
    """Generate the shared certificate/key fixtures exactly once per test run.

    Safe to run under a single process (`worker_id == "master"`, i.e. no
    `pytest-xdist`) or under multiple `pytest-xdist` worker processes.
    """
    from unit_tests.utils_for_test import (
        load_or_generate_cert_chain,  # noqa: PLC0415 local import to avoid slowing down collection
    )

    if worker_id == "master":
        # Not running under pytest-xdist: just generate directly, no coordination needed.
        load_or_generate_cert_chain()
        return

    # Under pytest-xdist, coordinate across worker processes with a lock file in the
    # shared base temp dir (one level above each worker's own temp dir).
    root_tmp_dir = tmp_path_factory.getbasetemp().parent
    done_marker = root_tmp_dir / "shared_test_fixtures.done"
    lock_path = root_tmp_dir / "shared_test_fixtures.lock"

    if done_marker.is_file():
        return

    try:
        fd = os.open(str(lock_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        # Another worker is already generating; wait for it to finish.
        while not done_marker.is_file():
            time.sleep(0.2)
        return

    try:
        load_or_generate_cert_chain()
        done_marker.touch()
    finally:
        os.close(fd)
