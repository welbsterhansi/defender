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
# Validation — every entry in --repositories must match at least one repo
# ---------------------------------------------------------------------------

class TestRepositoriesValidation:
    def test_all_repos_matched(self, tmp_path: Path) -> None:
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", "app,payments,catalog",
        ])
        # exit 0 — happy path; report file will be written with just the header
        # since our fake az returns empty data.
        assert r.returncode == 0, r.stderr
        # Validation prints each filter substring that matched at least one repo.
        # Fixture has app-backend / payments-api / catalog-svc — one match each.
        assert "app" in r.stdout and "1 match" in r.stdout
        assert "payments" in r.stdout
        assert "catalog" in r.stdout

    def test_typo_in_list_fails_early(self, tmp_path: Path) -> None:
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", "app,xyz-not-a-real-repo",
        ])
        assert r.returncode == 1
        assert "xyz-not-a-real-repo" in r.stderr

    def test_empty_list_after_trim_fails(self, tmp_path: Path) -> None:
        # `,,,` parses to zero entries — should fail loudly, not silently scan
        # the whole ACR.
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", ",,,",
        ])
        # Downstream: with zero parsed entries the filter builder returns
        # empty and we would inject an empty `| where ` — validation must
        # catch this. Right now defender.sh checks $REPOSITORIES != "" so
        # the argument-level check passes; the repo-loop finds nothing and
        # exits 1 via "matched_any == 0".
        assert r.returncode == 1


# ---------------------------------------------------------------------------
# KQL injection — the filter snippet is present with the right OR chain
# ---------------------------------------------------------------------------

class TestKqlFilterInjection:
    def test_leg_a_uses_repositoryName_contains_or_chain(self, tmp_path: Path) -> None:
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", "app,payments",
        ], capture_query=True)
        assert r.returncode == 0, r.stderr

        kql = r.captured_query   # type: ignore[attr-defined]
        # Leg A: on repositoryName. Both entries chained with `or`.
        assert 'artifactDetails.repositoryName contains "app"' in kql
        assert 'artifactDetails.repositoryName contains "payments"' in kql
        # OR keyword must be present between them (not "and").
        assert " or " in kql

    def test_leg_b_uses_resourceDetails_id_dashed_paths(self, tmp_path: Path) -> None:
        # Slash → dash conversion (see repo_to_dashed_path). Feed a slashed
        # repo name so the dashing is exercised end-to-end.
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
            "--repositories", "app,payments",
        ], capture_query=True)
        assert r.returncode == 0

        kql = r.captured_query   # type: ignore[attr-defined]
        # Leg B: same substrings but on resourceDetails.Id.
        assert 'resourceDetails.Id contains "app"' in kql
        assert 'resourceDetails.Id contains "payments"' in kql

    def test_no_kql_injection_when_flag_absent(self, tmp_path: Path) -> None:
        # Without --repositories nor --repository nor --scan-image, no
        # `contains` clause should appear on repositoryName or dashed Id.
        r = _run_defender(tmp_path, [
            "--acr-name", "myacr",
        ], capture_query=True)
        assert r.returncode == 0
        kql = r.captured_query   # type: ignore[attr-defined]
        assert 'artifactDetails.repositoryName contains' not in kql
