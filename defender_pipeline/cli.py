"""CLI dispatch — argparse-based subcommand router.

Subcommands (stubbed in P0.4; filled in by later tasks):

    scan     — Report-only ACR scan (P0.5)
    cluster  — OpenShift cross-reference (P0.6)
    expand   — Grouped CSV → per-CVE rows (P0.7)
    report   — HTML report generation   (P0.7)
    all      — scan → cluster → expand → report (P0.7)
    diff     — Byte-diff bash vs Python outputs (P0.5+, dev aid)

Each unimplemented subcommand exits with code 2 and a clear pointer to
the task that will implement it. This lets ``--help`` and the CLI shape
be exercised in tests before any real logic lands.
"""
from __future__ import annotations

import argparse
import sys
from typing import NoReturn

from defender_pipeline import __version__

# ---------------------------------------------------------------------------
# Exit codes (public contract — mirrors defender.sh / check_ocp.sh)
# ---------------------------------------------------------------------------
EXIT_OK = 0
EXIT_ERROR = 1
EXIT_NOT_IMPLEMENTED = 2   # stubbed subcommand
EXIT_PARTIAL_COVERAGE = 3  # matches check_ocp.sh contract (task P0.6)


def _not_yet_implemented(subcommand: str, task_id: str) -> NoReturn:
    """Bail out of a stubbed subcommand with a pointer to the task that
    will implement it."""
    print(
        f"error: subcommand `{subcommand}` is not yet implemented. "
        f"Tracking: task {task_id} (see docs/python-architecture.md).",
        file=sys.stderr,
    )
    sys.exit(EXIT_NOT_IMPLEMENTED)


# ---------------------------------------------------------------------------
# Subcommand handlers — stubs at P0.4. Signatures kept realistic so the
# tests can exercise --help and the eventual implementers only fill in
# the body.
# ---------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    """Report-only ACR scan. Implemented in P0.5."""
    _not_yet_implemented("scan", "P0.5")


def cmd_cluster(args: argparse.Namespace) -> int:
    """OpenShift cross-reference. Implemented in P0.6."""
    _not_yet_implemented("cluster", "P0.6")


def cmd_expand(args: argparse.Namespace) -> int:
    """Grouped CSV → per-CVE row explosion. Implemented in P0.7."""
    _not_yet_implemented("expand", "P0.7")


def cmd_report(args: argparse.Namespace) -> int:
    """HTML report generation. Implemented in P0.7."""
    _not_yet_implemented("report", "P0.7")


def cmd_all(args: argparse.Namespace) -> int:
    """Full pipeline: scan → cluster → expand → report. Implemented in P0.7."""
    _not_yet_implemented("all", "P0.7")


def cmd_diff(args: argparse.Namespace) -> int:
    """Byte-diff bash pipeline vs Python pipeline for validation.
    Implemented alongside P0.5 (once there's Python output to diff)."""
    _not_yet_implemented("diff", "P0.5")


# ---------------------------------------------------------------------------
# Parser construction
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defender_pipeline",
        description=(
            "Python API-first pipeline: ACR vulnerability scan via Azure SDKs "
            "+ OpenShift cross-reference via Kubernetes Python client + HTML "
            "report. Parallel to (and eventually replacing) the bash pipeline."
        ),
        epilog=(
            "See docs/python-architecture.md for design and "
            "docs/contracts/ for the output contracts this CLI preserves."
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"defender_pipeline {__version__}",
    )

    # Global options shared by all subcommands
    parser.add_argument(
        "--parallelism", type=int, default=8, metavar="N",
        help="Max concurrent SDK calls (default: 8; stays under Azure ARG "
             "rate limit of ~15 QPS per identity).",
    )
    parser.add_argument(
        "--log-format", choices=["text", "json"], default="text",
        help="Output log format (default: text — matches defender.sh audit "
             "trail line shape).",
    )
    parser.add_argument(
        "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
    )

    subs = parser.add_subparsers(dest="command", metavar="SUBCOMMAND", required=True)

    # scan --------------------------------------------------------------
    p_scan = subs.add_parser(
        "scan",
        help="Report-only ACR scan (batched two-phase via Azure SDKs).",
        description="Equivalent of `defender.sh` in report-only mode.",
    )
    p_scan.add_argument("--acr-name", required=True, metavar="NAME")
    p_scan.add_argument("--min-score", type=float, default=9.0)
    p_scan.add_argument("--max-score", type=float, default=10.0)
    scope = p_scan.add_mutually_exclusive_group()
    scope.add_argument("--repository", metavar="SUBSTRING",
                       help="Broad substring filter (contains semantics).")
    scope.add_argument("--repositories", metavar="a,b,c",
                       help="Controlled exact list of repo names.")
    scope.add_argument("--scan-image", metavar="REF",
                       help="Scan a specific repo, tag, or digest.")
    p_scan.add_argument("--skip-tags", action="store_true",
                        help="Skip Phase 1 tag_resolve; all rows get tag=N/A.")
    p_scan.add_argument("--output", default="vulnerable_images_report.csv",
                        metavar="PATH")
    p_scan.set_defaults(func=cmd_scan)

    # cluster -----------------------------------------------------------
    p_cluster = subs.add_parser(
        "cluster",
        help="OpenShift cross-reference (workloads × CVE CSV).",
        description="Equivalent of `check_ocp.sh`. Exits 3 on partial coverage.",
    )
    p_cluster.add_argument("--vulnerabilities", default="vulnerable_images_report.csv",
                           metavar="PATH")
    p_cluster.add_argument("--output", default="resultado_cruzamento.csv",
                           metavar="PATH")
    p_cluster.add_argument("--kubeconfig", metavar="PATH",
                           help="Override KUBECONFIG env / default location.")
    p_cluster.set_defaults(func=cmd_cluster)

    # expand ------------------------------------------------------------
    p_expand = subs.add_parser(
        "expand",
        help="Explode grouped rows into one row per CVE.",
        description="Equivalent of `expandcsv.py`.",
    )
    p_expand.add_argument("--cruzamento", default="resultado_cruzamento.csv",
                          metavar="PATH")
    p_expand.add_argument("--vulnerabilities", default="vulnerable_images_report.csv",
                          metavar="PATH")
    p_expand.add_argument("--output", default="expanded.csv", metavar="PATH")
    p_expand.set_defaults(func=cmd_expand)

    # report ------------------------------------------------------------
    p_report = subs.add_parser(
        "report",
        help="Render the single-file HTML report.",
        description="Equivalent of `report.py`.",
    )
    p_report.add_argument("--input", default="expanded.csv", metavar="PATH")
    p_report.add_argument("--output", default="vulnerability_report.html",
                          metavar="PATH")
    p_report.set_defaults(func=cmd_report)

    # all ---------------------------------------------------------------
    p_all = subs.add_parser(
        "all",
        help="Run the full pipeline: scan → cluster → expand → report.",
    )
    # Reuses scan's --acr-name; other flags accept the same defaults.
    p_all.add_argument("--acr-name", required=True, metavar="NAME")
    p_all.add_argument("--min-score", type=float, default=9.0)
    p_all.add_argument("--max-score", type=float, default=10.0)
    p_all.add_argument("--skip-tags", action="store_true")
    p_all.set_defaults(func=cmd_all)

    # diff --------------------------------------------------------------
    p_diff = subs.add_parser(
        "diff",
        help="Compare bash pipeline output vs Python pipeline output (dev aid).",
    )
    p_diff.add_argument("--bash-csv", required=True, metavar="PATH")
    p_diff.add_argument("--python-csv", required=True, metavar="PATH")
    p_diff.set_defaults(func=cmd_diff)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
