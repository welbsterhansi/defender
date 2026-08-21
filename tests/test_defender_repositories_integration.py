"""
Integration tests for `defender.sh --repositories` (task #37).

Two guarantees this file locks down:

1. Argument parsing safety: --repository, --repositories and --scan-image
   are mutually exclusive — combining them must fail early with a clear
   message, before any Azure call.

2. Filter injection: with --repositories a,b,c the KQL query file produced
   inside defender.sh must carry a `properties.additionalData.artifactDetails
   .repositoryName contains "a" or ... contains "b" or ... contains "c"`
   clause. We intercept the query file before it hits `az graph query` by
   planting a fake `az` on PATH that dumps the query and exits.

No live Azure calls — every path is mocked via a shim on PATH.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFENDER = REPO_ROOT / "defender.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("jq") is None,
    reason="bash or jq missing",
)


def _make_fake_az(bin_dir: Path, capture_query_to: Path | None = None) -> None:
    """
    Fake `az` that returns just enough for defender.sh's report-only path.
    If capture_query_to is set, `az graph query -q <file>` dumps the query
    file's contents there and returns an empty page (short-circuits the
    pagination loop after page 1).

    Dispatch keys match the full subcommand path (2 or 3 words) since
    Azure CLI subcommands go deeper than a single verb.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    capture_env = f'export CAPTURE_TO="{capture_query_to}"\n' if capture_query_to else ""
    az_body = f"""#!/usr/bin/env bash
{capture_env}
# `az acr show ...` → 2-word subcommand
if [ "$1 $2" = "acr show" ]; then exit 0; fi

# `az acr repository list ...` → 3-word subcommand
if [ "$1 $2 $3" = "acr repository list" ]; then
    printf 'app-backend\\npayments-api\\ncatalog-svc\\n'
    exit 0
fi

# `az acr manifest list-metadata ...` → 3-word subcommand
if [ "$1 $2 $3" = "acr manifest list-metadata" ]; then
    echo '[]'
    exit 0
fi

# `az graph query ...` — capture the -q value (query string, not a path).
# defender.sh invokes `az graph query -q "$(cat "$QUERY_FILE")"` so `-q`
# receives the KQL text directly.
if [ "$1 $2" = "graph query" ]; then
    qval=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -q) qval="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    if [ -n "${{qval:-}}" ] && [ -n "${{CAPTURE_TO:-}}" ]; then
        printf '%s\\n' "$qval" >> "$CAPTURE_TO"
    fi
    echo '{{"data":[],"skip_token":""}}'
    exit 0
fi
exit 0
"""
    az_path = bin_dir / "az"
    az_path.write_text(az_body, encoding="utf-8")
    az_path.chmod(0o755)


def _run_defender(tmp_path: Path, args: list[str],
                  capture_query: bool = False) -> subprocess.CompletedProcess:
    """Run defender.sh under tmp_path with a fake az planted on PATH."""
    bin_dir = tmp_path / "bin"
    query_dump = tmp_path / "captured_query.kql" if capture_query else None
    _make_fake_az(bin_dir, query_dump)

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"

    result = subprocess.run(
        [str(DEFENDER), *args],
        cwd=tmp_path, env=env,
        capture_output=True, text=True, check=False,
    )
    # attach the captured query onto the result for the caller
    result.captured_query = (   # type: ignore[attr-defined]
        query_dump.read_text(encoding="utf-8") if query_dump and query_dump.exists() else ""
    )
    return result


# ---------------------------------------------------------------------------
# Mutual exclusion — fails BEFORE any Azure call
# ---------------------------------------------------------------------------

class TestScopeFlagMutualExclusion:
    def test_repository_and_repositories_conflict(self, tmp_path: Path) -> None:
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repository", "app",
            "--repositories", "payments,catalog",
        ])
        assert r.returncode == 1
        assert "mutually exclusive" in r.stderr

    def test_repositories_and_scan_image_conflict(self, tmp_path: Path) -> None:
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", "app,payments",
            "--scan-image", "app-backend:latest",
        ])
        assert r.returncode == 1
        assert "mutually exclusive" in r.stderr

    def test_repository_and_scan_image_conflict(self, tmp_path: Path) -> None:
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repository", "app",
            "--scan-image", "app-backend:latest",
        ])
        assert r.returncode == 1
        assert "mutually exclusive" in r.stderr


# ---------------------------------------------------------------------------
# Validation — CONTROLLED list: exact match, empty/duplicate fail loud
# ---------------------------------------------------------------------------

class TestRepositoriesValidation:
    def test_all_repos_matched_exactly(self, tmp_path: Path) -> None:
        # Fixture repos are app-backend / payments-api / catalog-svc. Pass
        # the exact names — validation must accept.
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", "app-backend,payments-api,catalog-svc",
        ])
        assert r.returncode == 0, r.stderr
        assert "app-backend (exact match)" in r.stdout
        assert "payments-api (exact match)" in r.stdout
        assert "catalog-svc (exact match)" in r.stdout

    def test_substring_only_fails(self, tmp_path: Path) -> None:
        # Fixture has `app-backend` but NOT `app` — exact match must reject.
        # This is THE regression the review-round fixed: `contains` used to
        # accept this, capturing `app-backend` under `--repositories app`.
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", "app",
        ])
        assert r.returncode == 1
        assert "app" in r.stderr
        assert "not found" in r.stderr.lower()

    def test_typo_fails_early(self, tmp_path: Path) -> None:
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", "app-backend,xyz-not-real",
        ])
        assert r.returncode == 1
        assert "xyz-not-real" in r.stderr

    def test_empty_middle_entry_fails(self, tmp_path: Path) -> None:
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", "app-backend,,payments-api",
        ])
        assert r.returncode == 1
        assert "empty entry" in r.stderr.lower()

    def test_duplicate_entry_fails(self, tmp_path: Path) -> None:
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", "app-backend,payments-api,app-backend",
        ])
        assert r.returncode == 1
        assert "duplicate" in r.stderr.lower()
        assert "app-backend" in r.stderr

    def test_all_empty_fails(self, tmp_path: Path) -> None:
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", ",,,",
        ])
        assert r.returncode == 1


# ---------------------------------------------------------------------------
# KQL injection — anchored `contains "repositories-<dashed>-images-"` filter
# on the single (post-migration) query.
#
# Historical note: pre-2026-07-31 there was a "Leg A" (subassessments +
# `artifactDetails.repositoryName in (...)`) alongside "Leg B" (assessments +
# `resourceDetails.Id contains "repositories-…-images-"`). Microsoft retired
# subassessments so Leg A is gone. Only the Leg-B-style filter remains, and
# we assert Leg A's filter form does NOT leak back in.
# ---------------------------------------------------------------------------

class TestKqlFilterInjection:
    def test_leg_a_filter_shape_gone_post_migration(self, tmp_path: Path) -> None:
        """Leg A used `artifactDetails.repositoryName in (...)` which would
        target the retired subassessments type — must not appear anymore."""
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", "app-backend,payments-api",
        ], capture_query=True)
        assert r.returncode == 0, r.stderr
        kql = r.captured_query   # type: ignore[attr-defined]
        assert "artifactDetails.repositoryName in (" not in kql
        assert "artifactDetails.repositoryName contains" not in kql
        assert "subassessments" not in kql.lower()

    def test_leg_b_uses_anchored_contains(self, tmp_path: Path) -> None:
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", "app-backend,payments-api",
        ], capture_query=True)
        assert r.returncode == 0
        kql = r.captured_query   # type: ignore[attr-defined]
        # Leg B: `contains "repositories-<dashed>-images-"` — the bracketing
        # is what makes it exact match despite using `contains`.
        assert 'resourceDetails.Id contains "repositories-app-backend-images-"' in kql
        assert 'resourceDetails.Id contains "repositories-payments-api-images-"' in kql
        # Un-anchored `contains "app-backend"` must NOT appear on Leg B
        # (that would substring-match neighbors).
        assert 'resourceDetails.Id contains "app-backend"' not in kql

    def test_slashed_repo_is_dashed_on_leg_b(self, tmp_path: Path) -> None:
        # Extend fixture repos to include a slashed one.
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        az_body = """#!/usr/bin/env bash
export CAPTURE_TO="%s"
if [ "$1 $2" = "acr show" ]; then exit 0; fi
if [ "$1 $2 $3" = "acr repository list" ]; then
    printf 'team/app\\napp-backend\\n'
    exit 0
fi
if [ "$1 $2" = "graph query" ]; then
    qval=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -q) qval="$2"; shift 2 ;;
            *) shift ;;
        esac
    done
    [ -n "$qval" ] && printf '%%s\\n' "$qval" >> "$CAPTURE_TO"
    echo '{"data":[],"skip_token":""}'
    exit 0
fi
exit 0
""" % (tmp_path / "captured_query.kql")
        az_path = bin_dir / "az"
        az_path.write_text(az_body, encoding="utf-8")
        az_path.chmod(0o755)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        result = subprocess.run(
            [str(DEFENDER), "--acr-name", "myacr", "--repositories", "team/app"],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, result.stderr
        kql = (tmp_path / "captured_query.kql").read_text(encoding="utf-8")
        # Leg A's `in ("team/app")` form must not leak back in (subassessments retired).
        assert 'artifactDetails.repositoryName in ("team/app")' not in kql
        # Leg B: dashed anchor.
        assert 'resourceDetails.Id contains "repositories-team-app-images-"' in kql

    def test_no_kql_injection_when_flag_absent(self, tmp_path: Path) -> None:
        """Without --repositories / --repository, the KQL must not carry any
        `resourceDetails.Id contains "repositories-<x>-images-"` filter. The
        literal `repositories-` may still appear inside the hardcoded
        `extract(@"repositories-(.+)-images-…")` regex — that's the KQL
        pattern, not injected data — so we assert on the operator-controlled
        filter form specifically."""
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
        ], capture_query=True)
        assert r.returncode == 0
        kql = r.captured_query   # type: ignore[attr-defined]
        assert 'artifactDetails.repositoryName in (' not in kql
        assert 'resourceDetails.Id contains "repositories-' not in kql
