"""
Integration tests for lib/logging.sh — log persistence to logs/run-*.log
while keeping realtime output on the terminal.

Contract (task #39):
  - logs/ directory auto-created
  - log file named `run-YYYYMMDD-HHMMSS.log` (UTC)
  - header includes timestamp, script name, mode, args, log_file, pid
  - subprocess stdout/stderr still reach the caller (realtime preserved)
  - flag names hinting at secrets (--token, --password, --secret, --key)
    trigger value redaction in the header
  - COVERAGE summary from check_ocp.sh appears in the log
  - RBAC_ERR line from check_ocp.sh appears in the log
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFENDER = REPO_ROOT / "defender.sh"
CHECK_OCP = REPO_ROOT / "check_ocp.sh"

pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None or shutil.which("jq") is None,
    reason="bash or jq missing",
)


def _make_fake_az(bin_dir: Path) -> None:
    """Minimal fake `az` for defender.sh report-only path."""
    bin_dir.mkdir(parents=True, exist_ok=True)
    body = """#!/usr/bin/env bash
if [ "$1 $2" = "acr show" ]; then exit 0; fi
if [ "$1 $2 $3" = "acr repository list" ]; then
    printf 'app-backend\\npayments-api\\n'; exit 0
fi
if [ "$1 $2" = "graph query" ]; then
    echo '{"data":[],"skip_token":""}'; exit 0
fi
exit 0
"""
    p = bin_dir / "az"
    p.write_text(body, encoding="utf-8")
    p.chmod(0o755)


def _make_fake_oc(bin_dir: Path, mode: str) -> None:
    """
    Fake `oc`. `mode`:
      - 'ok':   returns one healthy namespace with one pod
      - 'rbac': returns one namespace where `oc get pods` is forbidden
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    if mode == "ok":
        body = """#!/usr/bin/env bash
if [ "$1 $2" = "get projects" ]; then printf 'prd-ok\\n'; exit 0; fi
if [ "$1 $2" = "get pods" ]; then echo '{"items":[]}'; exit 0; fi
"""
    elif mode == "rbac":
        body = """#!/usr/bin/env bash
if [ "$1 $2" = "get projects" ]; then printf 'prd-locked\\n'; exit 0; fi
if [ "$1 $2" = "get pods" ]; then
    echo 'Error from server (Forbidden): pods is forbidden' >&2
    exit 1
fi
"""
    else:
        raise ValueError(mode)
    p = bin_dir / "oc"
    p.write_text(body, encoding="utf-8")
    p.chmod(0o755)


def _empty_vulns_csv(path: Path) -> Path:
    """Minimal LIST_FILE — only the header — accepted by check_ocp.sh."""
    header = (
        '"repository","digest","tag","cvssScore","cveId","severity",'
        '"packageCategory","packageLanguage","packageName","currentVersion",'
        '"fixedVersion","patchable","remediation","fixStatus","cveAgeDays",'
        '"isInExploitKit","hasPublishedExploit","hasVerifiedExploit",'
        '"lastPushedToRegistryUTC"'
    )
    path.write_text(header + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# defender.sh: log file created with proper header + realtime preserved
# ---------------------------------------------------------------------------

class TestDefenderLogging:
    def test_log_file_created_with_expected_name(self, tmp_path: Path) -> None:
        bin_dir = tmp_path / "bin"
        _make_fake_az(bin_dir)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"

        result = subprocess.run(
            [str(DEFENDER), "--acr-name", "myacr", "--min-score", "9"],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, result.stderr

        logs = list((tmp_path / "logs").glob("run-*.log"))
        assert len(logs) == 1, f"expected 1 log file, got {logs}"
        # Task #40: name includes PID → collision-safe under parallel CI.
        assert re.match(r"run-\d{8}-\d{6}-\d+\.log$", logs[0].name), \
            f"log name should be run-YYYYMMDD-HHMMSS-<pid>.log, got {logs[0].name}"

    def test_log_header_contains_context(self, tmp_path: Path) -> None:
        bin_dir = tmp_path / "bin"
        _make_fake_az(bin_dir)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"

        subprocess.run(
            [str(DEFENDER), "--acr-name", "myacr", "--min-score", "9"],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        log = next((tmp_path / "logs").glob("run-*.log"))
        content = log.read_text(encoding="utf-8")

        # Header markers
        assert "=== defender-local-actions run ===" in content
        assert "script:     defender.sh" in content
        assert "mode:       report-only" in content
        assert "--acr-name myacr" in content
        # ISO 8601 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)
        assert re.search(r"timestamp:\s+\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", content)

    def test_realtime_output_preserved_on_stdout(self, tmp_path: Path) -> None:
        """The operator must still see logs on the terminal — file mirrors,
        does not replace."""
        bin_dir = tmp_path / "bin"
        _make_fake_az(bin_dir)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"

        result = subprocess.run(
            [str(DEFENDER), "--acr-name", "myacr", "--min-score", "9"],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        # subprocess stdout captures what the terminal would have seen.
        assert "Processing complete" in result.stdout
        assert "Validating Azure Container Registry" in result.stdout
        # And the same content is in the log file.
        log_content = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        assert "Processing complete" in log_content
        assert "Validating Azure Container Registry" in log_content

    def test_mode_reflects_scan_image(self, tmp_path: Path) -> None:
        # We're not exercising the full scan flow (fake az doesn't resolve
        # tags), but we can confirm the mode string in the header is right.
        bin_dir = tmp_path / "bin"
        _make_fake_az(bin_dir)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"

        subprocess.run(
            [str(DEFENDER), "--acr-name", "myacr",
             "--scan-image", "app-backend"],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        log = next((tmp_path / "logs").glob("run-*.log"))
        assert "mode:       scan-image" in log.read_text(encoding="utf-8")

    def test_dry_run_mode_marked(self, tmp_path: Path) -> None:
        bin_dir = tmp_path / "bin"
        _make_fake_az(bin_dir)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"

        subprocess.run(
            [str(DEFENDER), "--acr-name", "myacr", "--min-score", "9",
             "--dry-run"],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        log = next((tmp_path / "logs").glob("run-*.log"))
        assert "+dry-run" in log.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# check_ocp.sh: coverage summary + RBAC_ERR captured in log
# ---------------------------------------------------------------------------

class TestCheckOcpLogging:
    def test_log_captures_coverage_summary(self, tmp_path: Path) -> None:
        bin_dir = tmp_path / "bin"
        _make_fake_oc(bin_dir, "ok")
        vulns = _empty_vulns_csv(tmp_path / "vulns.csv")
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"

        subprocess.run(
            [str(CHECK_OCP), str(vulns), str(tmp_path / "out.csv")],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        log = next((tmp_path / "logs").glob("run-*.log"))
        content = log.read_text(encoding="utf-8")
        assert "=== Coverage summary ===" in content
        assert "COVERAGE: COMPLETE" in content
        assert "script:     check_ocp.sh" in content
        assert "mode:       cross-reference" in content

    def test_log_captures_rbac_error(self, tmp_path: Path) -> None:
        bin_dir = tmp_path / "bin"
        _make_fake_oc(bin_dir, "rbac")
        vulns = _empty_vulns_csv(tmp_path / "vulns.csv")
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"

        result = subprocess.run(
            [str(CHECK_OCP), str(vulns), str(tmp_path / "out.csv")],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        assert result.returncode == 3, "RBAC error must produce partial-coverage exit"

        log = next((tmp_path / "logs").glob("run-*.log"))
        content = log.read_text(encoding="utf-8")
        # Both the WARN line and the coverage bucket must be in the file.
        assert "prd-locked" in content
        assert "RBAC error" in content
        assert "COVERAGE: PARTIAL" in content


# ---------------------------------------------------------------------------
# Secret scrubbing in the header
# ---------------------------------------------------------------------------

class TestSecretScrubbing:
    def _run_init_with_fake_args(self, tmp_path: Path,
                                 args: list[str]) -> Path:
        """Source lib/logging.sh in isolation and call init_logging with
        arbitrary args to exercise the scrubber without needing a fake
        defender.sh flow."""
        script = f"""#!/usr/bin/env bash
set -euo pipefail
cd "{tmp_path}"
source "{REPO_ROOT}/lib/logging.sh"
init_logging "test-script" "test-mode" {' '.join(f'"{a}"' for a in args)}
"""
        p = tmp_path / "runner.sh"
        p.write_text(script, encoding="utf-8")
        p.chmod(0o755)
        subprocess.run([str(p)], cwd=tmp_path,
                       capture_output=True, text=True, check=False)
        return next((tmp_path / "logs").glob("run-*.log"))

    def test_token_flag_value_is_redacted(self, tmp_path: Path) -> None:
        log = self._run_init_with_fake_args(
            tmp_path, ["--token", "SUPER-SECRET-XYZ-42", "--min-score", "9"]
        )
        content = log.read_text(encoding="utf-8")
        assert "<redacted>" in content
        assert "SUPER-SECRET-XYZ-42" not in content, \
            "secret leaked into the log file"
        # The flag name itself is fine to log.
        assert "--token" in content
        # Non-secret flags pass through unchanged.
        assert "--min-score 9" in content

    def test_password_and_secret_flags_are_redacted(self, tmp_path: Path) -> None:
        log = self._run_init_with_fake_args(
            tmp_path,
            ["--password", "hunter2", "--secret", "abc", "--api-key", "xyz"],
        )
        content = log.read_text(encoding="utf-8")
        for leak in ("hunter2", "abc", "xyz"):
            assert leak not in content, f"{leak!r} leaked in log"

    def test_ordinary_flag_values_pass_through(self, tmp_path: Path) -> None:
        log = self._run_init_with_fake_args(
            tmp_path, ["--acr-name", "myacr", "--repositories", "app,payments"]
        )
        content = log.read_text(encoding="utf-8")
        assert "myacr" in content
        assert "app,payments" in content
        assert "<redacted>" not in content


# ---------------------------------------------------------------------------
# Task #40: graceful degradation + trap composition + unique PID in name
# ---------------------------------------------------------------------------

class TestGracefulDegradation:
    """When tee/process-substitution is unavailable, init_logging must WARN
    and let the caller continue with terminal-only output. Never kill the run."""

    def test_degrades_when_tee_missing(self, tmp_path: Path) -> None:
        # PATH points to a directory with NO `tee` — the probe should fail
        # gracefully and the caller keeps running. We simulate by pointing
        # PATH to an empty bin dir + stubbing bash builtins we still need.
        empty_bin = tmp_path / "empty_bin"
        empty_bin.mkdir()
        # Bring in the minimum so the shell can still work — but no tee.
        for tool in ("bash", "mkdir", "date", "sed", "cat"):
            real = shutil.which(tool)
            if real:
                (empty_bin / tool).symlink_to(real)
        env = {"PATH": str(empty_bin), "HOME": os.environ.get("HOME", "/tmp")}

        runner = tmp_path / "run.sh"
        runner.write_text(f"""#!/usr/bin/env bash
set -euo pipefail
cd "{tmp_path}"
source "{REPO_ROOT}/lib/logging.sh"
init_logging "test" "test-mode" --foo bar
echo "still alive after init_logging"
""", encoding="utf-8")
        runner.chmod(0o755)

        result = subprocess.run(
            [str(runner)], cwd=tmp_path, env=env,
            capture_output=True, text=True, check=False,
        )
        # Caller survived (exit 0) even though tee wasn't available.
        assert result.returncode == 0, (
            f"init_logging killed the run when tee was missing:\n{result.stderr}"
        )
        # Warning surfaced.
        assert "logging" in result.stderr.lower()
        assert "not" in result.stderr.lower()
        # And the post-init line printed — proving the shell kept going.
        assert "still alive after init_logging" in result.stdout

    def test_degrades_when_logs_dir_not_writable(self, tmp_path: Path) -> None:
        # Point LOG_DIR at a path that can't be created (parent is a file).
        blocker = tmp_path / "notadir"
        blocker.write_text("i am a file, not a directory\n")

        runner = tmp_path / "run.sh"
        runner.write_text(f"""#!/usr/bin/env bash
set -euo pipefail
export LOG_DIR="{blocker}/logs"
source "{REPO_ROOT}/lib/logging.sh"
init_logging "test" "test-mode"
echo "post-init OK"
""", encoding="utf-8")
        runner.chmod(0o755)

        result = subprocess.run(
            [str(runner)], cwd=tmp_path,
            capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0
        assert "could not create" in result.stderr.lower()
        assert "post-init OK" in result.stdout


class TestExitTrapComposition:
    """init_logging must not clobber a pre-existing EXIT trap. And a caller
    that later adds its own trap via _add_exit_trap must also compose."""

    def test_preexisting_trap_is_preserved(self, tmp_path: Path) -> None:
        marker = tmp_path / "marker"
        runner = tmp_path / "run.sh"
        runner.write_text(f"""#!/usr/bin/env bash
set -euo pipefail
cd "{tmp_path}"
trap 'echo "PREEXISTING RAN" > "{marker}"' EXIT
source "{REPO_ROOT}/lib/logging.sh"
init_logging "test" "test-mode"
echo "body"
""", encoding="utf-8")
        runner.chmod(0o755)
        result = subprocess.run(
            [str(runner)], cwd=tmp_path,
            capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, result.stderr
        assert marker.exists(), (
            "init_logging clobbered the pre-existing EXIT trap"
        )
        assert marker.read_text().strip() == "PREEXISTING RAN"

    def test_defender_cleanup_still_runs_alongside_logging(
        self, tmp_path: Path
    ) -> None:
        """End-to-end proof: defender.sh's own EXIT trap (cleans QUERY_FILE
        + REPORT_TMP) must run alongside the tee-flush trap set by
        init_logging. If either is dropped, we regress."""
        bin_dir = tmp_path / "bin"
        _make_fake_az(bin_dir)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"

        result = subprocess.run(
            [str(DEFENDER), "--acr-name", "myacr", "--min-score", "9"],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, result.stderr

        # 1) Log was written (tee flush trap ran).
        log = next((tmp_path / "logs").glob("run-*.log"))
        assert "Processing complete" in log.read_text(encoding="utf-8")

        # 2) defender.sh's cleanup trap ran too: REPORT_TMP files must be
        # gone. defender.sh names them "<REPORT_FILE>.tmp.<pid>" and moves
        # them onto the final path on success — no leftovers on disk.
        leftover_tmps = list(tmp_path.glob("*.csv.tmp.*"))
        assert not leftover_tmps, (
            f"defender.sh cleanup was clobbered — leftover tmp files: {leftover_tmps}"
        )


class TestUniquePidInName:
    """Two runs in the same second must produce two distinct log files."""

    def test_two_runs_produce_distinct_files(self, tmp_path: Path) -> None:
        bin_dir = tmp_path / "bin"
        _make_fake_az(bin_dir)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"

        for _ in range(2):
            subprocess.run(
                [str(DEFENDER), "--acr-name", "myacr", "--min-score", "9"],
                cwd=tmp_path, env=env,
                capture_output=True, text=True, check=False,
            )
        logs = sorted((tmp_path / "logs").glob("run-*.log"))
        assert len(logs) == 2, (
            f"expected 2 distinct log files (PID differs), got {logs}"
        )
        assert logs[0].name != logs[1].name
