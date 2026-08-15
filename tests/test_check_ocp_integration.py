"""
Integration tests for check_ocp.sh — the RBAC / coverage hardening (#28–#30).

Runs the real script end-to-end with a fake `oc` planted first on PATH,
so we cover the exact bash + jq behavior without touching a live cluster.
Each test scenario answers: does the script classify this namespace state
correctly, emit an actionable WARN, and use the right coverage exit code?

Skip cleanly if bash or jq are missing.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECK_OCP = REPO_ROOT / "check_ocp.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("jq") is None,
    reason="bash or jq missing",
)


def _make_fake_oc(tmp_path: Path, script_body: str) -> Path:
    """Write a fake `oc` executable under tmp_path/bin and return its dir."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(parents=True, exist_ok=True)
    fake_oc = bin_dir / "oc"
    fake_oc.write_text("#!/usr/bin/env bash\n" + script_body, encoding="utf-8")
    fake_oc.chmod(0o755)
    return bin_dir


def _empty_vulns_csv(path: Path) -> Path:
    """A LIST_FILE with only the header — check_ocp accepts this."""
    header = (
        '"repository","digest","tag","cvssScore","cveId","severity",'
        '"packageCategory","packageLanguage","packageName","currentVersion",'
        '"fixedVersion","patchable","remediation","fixStatus","cveAgeDays",'
        '"isInExploitKit","hasPublishedExploit","hasVerifiedExploit",'
        '"lastPushedToRegistryUTC"'
    )
    path.write_text(header + "\n", encoding="utf-8")
    return path


def _run_check_ocp(tmp_path: Path, fake_oc_body: str) -> subprocess.CompletedProcess:
    """Prepare env with fake oc + empty vulns CSV, run check_ocp.sh, capture output."""
    bin_dir = _make_fake_oc(tmp_path, fake_oc_body)
    vulns = _empty_vulns_csv(tmp_path / "vulns.csv")
    out = tmp_path / "resultado.csv"

    env = os.environ.copy()
    env["PATH"] = f"{bin_dir}:{env['PATH']}"

    return subprocess.run(
        [str(CHECK_OCP), str(vulns), str(out)],
        cwd=tmp_path, env=env,
        capture_output=True, text=True, check=False,
    )


# ---------------------------------------------------------------------------
# One test per namespace state
# ---------------------------------------------------------------------------

class TestNamespaceStates:
    def test_success_with_pods_exits_0(self, tmp_path: Path) -> None:
        body = '''
        if [ "$1 $2" = "get projects" ]; then printf 'prd-ok\\n'; exit 0; fi
        if [ "$1 $2" = "get pods" ]; then
            echo '{"items":[{"metadata":{"namespace":"prd-ok","name":"x","ownerReferences":[{"kind":"ReplicaSet","name":"rs"}]},"status":{"containerStatuses":[{"imageID":"docker-pullable://r/x@sha256:aaa1111111111111111111111111111111111111111111111111111111111111"}]}}]}'
            exit 0
        fi
        '''
        result = _run_check_ocp(tmp_path, body)
        assert result.returncode == 0, result.stderr + result.stdout
        assert "COVERAGE: COMPLETE" in result.stdout
        assert "Pods processed:            1" in result.stdout

    def test_no_pods_exits_0(self, tmp_path: Path) -> None:
        body = '''
        if [ "$1 $2" = "get projects" ]; then printf 'prd-idle\\n'; exit 0; fi
        if [ "$1 $2" = "get pods" ]; then echo '{"items":[]}'; exit 0; fi
        '''
        result = _run_check_ocp(tmp_path, body)
        assert result.returncode == 0
        assert "COVERAGE: COMPLETE" in result.stdout
        assert "Analyzed (OK, no pods):    1" in result.stdout

    def test_rbac_error_exits_3_with_actionable_warn(self, tmp_path: Path) -> None:
        body = '''
        if [ "$1 $2" = "get projects" ]; then printf 'prd-locked\\n'; exit 0; fi
        if [ "$1 $2" = "get pods" ]; then
            echo 'Error from server (Forbidden): pods is forbidden' >&2
            exit 1
        fi
        '''
        result = _run_check_ocp(tmp_path, body)
        assert result.returncode == 3, "RBAC error must trigger partial-coverage exit 3"
        # WARN mentions the namespace AND the suggested action
        assert "prd-locked" in result.stderr
        assert "RBAC error" in result.stderr
        assert "grant get/list pods" in result.stderr
        # Coverage summary reflects the failure
        assert "COVERAGE: PARTIAL" in result.stdout
        assert "RBAC errors:               1" in result.stdout
        assert "prd-locked" in result.stdout    # listed under RBAC-blocked
        # And stderr from `oc` is NOT included verbatim in stdout (avoid leak)
        assert "Error from server" not in result.stdout

    def test_generic_oc_error_exits_3(self, tmp_path: Path) -> None:
        body = '''
        if [ "$1 $2" = "get projects" ]; then printf 'prd-boom\\n'; exit 0; fi
        if [ "$1 $2" = "get pods" ]; then
            echo 'Unable to connect to the server: EOF' >&2
            exit 1
        fi
        '''
        result = _run_check_ocp(tmp_path, body)
        assert result.returncode == 3
        assert "oc failed" in result.stderr
        # Preview of stderr surfaced (bounded, redacted intent)
        assert "Unable to connect" in result.stderr
        assert "COVERAGE: PARTIAL" in result.stdout
        assert "Other oc errors:           1" in result.stdout

    def test_parse_error_exits_3(self, tmp_path: Path) -> None:
        body = '''
        if [ "$1 $2" = "get projects" ]; then printf 'prd-junk\\n'; exit 0; fi
        if [ "$1 $2" = "get pods" ]; then echo 'not-json-at-all'; exit 0; fi
        '''
        result = _run_check_ocp(tmp_path, body)
        assert result.returncode == 3
        assert "parse error" in result.stderr
        assert "COVERAGE: PARTIAL" in result.stdout
        assert "Parse errors:              1" in result.stdout


# ---------------------------------------------------------------------------
# End-to-end scenario mixing several states
# ---------------------------------------------------------------------------

class TestMixedScenario:
    def test_summary_and_exit_reflect_all_states(self, tmp_path: Path) -> None:
        body = '''
        if [ "$1 $2" = "get projects" ]; then
            # 1 ok, 1 rbac, 1 parse-broken, 1 no-pods, 1 platform (ignored)
            printf 'prd-ok\\nprd-rbac\\nprd-broken\\nprd-idle\\nopenshift-monitoring\\n'
            exit 0
        fi
        if [ "$1 $2" = "get pods" ]; then
            ns=""
            while [ $# -gt 0 ]; do [ "$1" = "-n" ] && ns="$2"; shift; done
            case "$ns" in
                prd-ok) echo '{"items":[{"metadata":{"namespace":"prd-ok","name":"a","ownerReferences":[{"kind":"ReplicaSet","name":"rs"}]},"status":{"containerStatuses":[{"imageID":"docker-pullable://r/a@sha256:1111111111111111111111111111111111111111111111111111111111111111"}]}}]}' ;;
                prd-rbac) echo 'forbidden' >&2; exit 1 ;;
                prd-broken) echo 'garbage' ;;
                prd-idle) echo '{"items":[]}' ;;
            esac
            exit 0
        fi
        '''
        result = _run_check_ocp(tmp_path, body)

        assert result.returncode == 3, "any failure yields partial exit"

        # All 5 buckets accounted for in the summary
        assert "Namespaces visible:        5" in result.stdout
        assert "Ignored (platform filter): 1" in result.stdout
        assert "Analyzed (OK, with pods):  1" in result.stdout
        assert "Analyzed (OK, no pods):    1" in result.stdout
        assert "RBAC errors:               1" in result.stdout
        assert "Parse errors:              1" in result.stdout
        assert "COVERAGE: PARTIAL — 2 namespace(s) failed" in result.stdout
