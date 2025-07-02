"""Generate XMSS and XMSSMT keys in parallel.

* Uses Python's multiprocessing.Pool with safe Ctrl-C handling.
* CLI flags:
    -j / --jobs            : number of worker processes
    -c / --chunksize       : tasks bundled per queue hop
    --serial-bodies (default) / --parallel-bodies
* Heavy-XMSS helper (_is_heavy_xmss) and the new _is_heavy_xmssmt.

All keys are written to data/keys/xmss_xmssmt_keys_verbose
"""

import argparse
import os
import sys
import time
from multiprocessing import Pool, cpu_count, get_context
from typing import Iterable, Sequence, Tuple

from pq_logic.combined_factory import CombinedKeyFactory
from resources.ca_ra_utils import (
    is_nist_approved_xmss,
    is_nist_approved_xmssmt,
)
from resources.keyutils import generate_key, save_key

KEY_DIR: str = "data/keys/xmss_xmssmt_keys_verbose"

ALL_REQUEST_BODY_NAMES: list[str] = [
    "ir",
    "p10cr",
    "cr",
    "kur",
    "ccr",
    "added-protection-inner-ir",
    "added-protection-inner-cr",
    "added-protection-inner-kur",
    "added-protection-inner-p10cr",
    "added-protection-inner-ccr",
    "batch-inner-ir",
    "batch-inner-cr",
    "batch-inner-kur",
    "batch-inner-p10cr",
    "batch-inner-ccr",
]

REASONS_APPROVED: list[str] = [
    "bad_pop",
    "popo",
    "bad_params",
    "bad_key_size",
    "exhausted",
    "cert_conf",
]
REASON_DISAPPROVED: str = "bad_pop"

_Task = Tuple[str, str, str]  # alias for readability


def _print_time_taken(start: float) -> str:
    """Return a human-readable time."""
    elapsed: float = time.time() - start
    if elapsed < 60:
        return f"{elapsed:.2f}s"
    if elapsed < 3_600:
        return f"{elapsed / 60:.2f} min"
    return f"{elapsed / 3_600:.2f} h"


def _key_path(alg: str, body: str, reason: str) -> str:
    """Get the file path for a key based on algorithm, body, and reason."""
    alg_name: str = alg.replace("/", "_layers_") if "/" in alg else alg
    return os.path.join(KEY_DIR, f"{alg_name}_{body}_{reason}.pem")


def _needs_key(alg: str, body: str, reason: str) -> bool:
    """Check if a key for the given (alg, body, reason) triple needs to be generated."""
    return not os.path.exists(_key_path(alg, body, reason))


def _generate_key_and_save(alg: str, body: str, reason: str) -> None:
    """Generate and save a key unless it already exists."""
    path: str = _key_path(alg, body, reason)
    if not os.path.exists(path):
        key = generate_key(alg.lower())
        save_key(key, path)


def _is_heavy_xmss(alg: str) -> bool:
    """Identify XMSS variants with height 20 (slowest in single-tree family).

    Expected format:  xmss-<hash_alg>_<height>_<security>
    Example        :  xmss-sha2_20_256
    """
    alg_low: str = alg.lower()
    if not alg_low.startswith("xmss-"):
        return False
    parts = alg_low.split("_")  # ['xmss', 'sha2', '20', '256']
    return parts[1] == "20"


def _is_heavy_xmssmt(alg: str) -> bool:
    """Heavy = total height ≥ 40  **or**  layer-count ≥ 4.

    Format (liboqs style, lower-case expected):
        xmssmt-<hash_alg>_<height>/<layers>_<bits_output>
        e.g. xmssmt-sha2_40/8_256
    """
    alg_low: str = alg.lower()
    if not alg_low.startswith("xmssmt-"):
        return False
    try:
        # after the first '_' we have '<height>/<layers>'
        height_layers: str = alg_low.split("_", 2)[1]  # '40/8'
        height_str, layers_str = height_layers.split("/", 1)
        height: int = int(height_str)
        layers: int = int(layers_str)
        return height >= 40 or layers >= 4
    except (IndexError, ValueError):
        return False  # malformed name → treat as not-heavy


def _filter_existing(tasks: Sequence[_Task]) -> list[_Task]:
    """Drop triples that already have a saved key."""
    return [t for t in tasks if _needs_key(*t)]


def _build_tasks_for_body(family: str, body: str) -> list[_Task]:
    """Build all (alg, body, reason) triples for one request-body name.

    `family` must be "xmss" or "xmssmt".
    """
    algs: Iterable[str] = CombinedKeyFactory.get_stateful_sig_algorithms()[family]
    approved = is_nist_approved_xmss if family == "xmss" else is_nist_approved_xmssmt

    tasks: list[_Task] = []
    for alg in algs:
        if not approved(alg):
            tasks.append((alg, body, REASON_DISAPPROVED))
        else:
            tasks.extend((alg, body, r) for r in REASONS_APPROVED)
    return _filter_existing(tasks)


def _worker(task: _Task) -> str:
    """Generate a single key; executed in a child process."""
    alg, body, reason = task
    if not _needs_key(alg, body, reason):
        return f"SKIP  {alg.lower()}_{body}_{reason}"
    _generate_key_and_save(alg, body, reason)
    return f"OK    {alg.lower()}_{body}_{reason}"


def _run_pool(
    tasks: Iterable[_Task],
    label: str,
    *,
    procs: int | None,
    chunksize: int,
) -> None:
    """Print out `tasks` to a Pool, showing progress."""
    os.makedirs(KEY_DIR, exist_ok=True)

    task_list: list[_Task] = list(tasks)
    total: int = len(task_list)
    if total == 0:
        print(f"✔ {label}: nothing to do")
        return

    print(f"\n▶ {label}: {total} tasks • {procs or cpu_count()} processes • chunksize {chunksize}")
    start: float = time.time()

    ctx = get_context("fork") if sys.platform != "win32" else None
    PoolCls = ctx.Pool if ctx else Pool

    try:
        with PoolCls(processes=procs or cpu_count()) as pool:
            try:
                for idx, msg in enumerate(pool.imap_unordered(_worker, task_list, chunksize=chunksize), 1):
                    elapsed = _print_time_taken(start)
                    print(
                        f"[{idx:>{len(str(total))}}/{total}] {msg:75} {elapsed}",
                        flush=True,
                    )
            except KeyboardInterrupt:
                print("\n↯  Ctrl-C detected – terminating workers …", file=sys.stderr)
                pool.terminate()
                pool.join()
                raise
    except KeyboardInterrupt:
        print("✖  Generation aborted by user.", file=sys.stderr)
        sys.exit(1)

    print(f"✔ Finished {label} in {_print_time_taken(start)}")


def _generate_family(
    family: str,
    *,
    serial_bodies: bool,
    processes: int | None,
    chunksize: int,
) -> None:
    """Generate all keys for one algorithm family (XMSS or XMSSMT)."""
    if serial_bodies:
        for body in ALL_REQUEST_BODY_NAMES:
            tasks = _build_tasks_for_body(family, body)
            _run_pool(tasks, f"{family.upper()}:{body}", procs=processes, chunksize=chunksize)
    else:
        all_tasks: list[_Task] = []
        for body in ALL_REQUEST_BODY_NAMES:
            all_tasks.extend(_build_tasks_for_body(family, body))
        _run_pool(all_tasks, family.upper(), procs=processes, chunksize=chunksize)


def _parse_cli() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Generate XMSS / XMSSMT keys in parallel",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "family",
        choices=["xmss", "xmssmt", "all"],
        nargs="?",
        default="all",
        help="Which key family to generate",
    )
    parser.add_argument(
        "-j",
        "--jobs",
        "--processes",
        dest="processes",
        type=int,
        default=None,
        metavar="N",
        help="Worker processes (default: logical CPU count)",
    )
    parser.add_argument(
        "-c",
        "--chunksize",
        type=int,
        default=8,
        metavar="N",
        help="Tasks bundled per queue hop (1 disables batching)",
    )
    body_group = parser.add_mutually_exclusive_group()
    body_group.add_argument(
        "--serial-bodies",
        dest="serial_bodies",
        action="store_true",
        default=True,
        help="Finish one body batch before starting the next (default)",
    )
    body_group.add_argument(
        "--parallel-bodies",
        dest="serial_bodies",
        action="store_false",
        help="Mix all body names in a single pool run",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_cli()
    # Example usage:
    # python3 generate_xmss_keys.py xmssmt -j 12 --chunksize 8
    if args.family in ("xmss", "all"):
        _generate_family(
            "xmss",
            serial_bodies=args.serial_bodies,
            processes=args.processes,
            chunksize=args.chunksize,
        )

    if args.family in ("xmssmt", "all"):
        _generate_family(
            "xmssmt",
            serial_bodies=args.serial_bodies,
            processes=args.processes,
            chunksize=args.chunksize,
        )

    print("\n🎉  All requested keys generated.")
