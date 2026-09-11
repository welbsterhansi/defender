"""
Integration tests for lib/logging.sh — best-effort structured logging.

Design contract (task #41):
  - init_logging never aborts the caller; on any failure LOG_FILE stays
    empty and log_* helpers still work (terminal only).
  - log_info / log_warn / log_error write to stderr always, and append to
    LOG_FILE best-effort (guarded with `|| true`).
  - Log file (when created) starts with a header block and contains
    structured `[ISO_TS] LEVEL  message` lines for critical events.
  - Name includes PID → collision-safe under parallel CI.
  - Scrubbing: values of --token/--password/--secret/--key flags become
    <redacted> in the header.
  - The engine (defender.sh / check_ocp.sh) completes normally even when
    file logging is disabled — logging is evidence, not truth.
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
    header = (
        '"repository","digest","tag","cvssScore","cveId","severity",'
        '"packageCategory","packageLanguage","packageName","currentVersion",'
        '"fixedVersion","patchable","remediation","fixStatus","cveAgeDays",'
        '"isInExploitKit","hasPublishedExploit","hasVerifiedExploit",'
        '"lastPushedToRegistryUTC"'
    )
    path.write_text(header + "\n", encoding="utf-8")
    return path


def _run_bash_script(body: str, tmp_path: Path,
                     env_extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    """Write and execute a small bash script that sources lib/logging.sh."""
    runner = tmp_path / f"run-{os.getpid()}.sh"
    runner.write_text(f"#!/usr/bin/env bash\nset -euo pipefail\n{body}\n",
                      encoding="utf-8")
    runner.chmod(0o755)
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    return subprocess.run([str(runner)], cwd=tmp_path, env=env,
                          capture_output=True, text=True, check=False)


# ---------------------------------------------------------------------------
# init_logging: file creation, header, PID in name
# ---------------------------------------------------------------------------

class TestInitLoggingFile:
    def test_creates_file_with_pid_in_name(self, tmp_path: Path) -> None:
        r = _run_bash_script(f"""
source "{REPO_ROOT}/lib/logging.sh"
init_logging "unit-test" "test-mode" --foo bar
""", tmp_path)
        assert r.returncode == 0, r.stderr
        logs = list((tmp_path / "logs").glob("run-*.log"))
        assert len(logs) == 1
        # PID makes the name collision-safe under parallel CI.
        assert re.match(r"run-\d{8}-\d{6}-\d+\.log$", logs[0].name), logs[0].name

    def test_header_contains_context(self, tmp_path: Path) -> None:
        _run_bash_script(f"""
source "{REPO_ROOT}/lib/logging.sh"
init_logging "unit-test" "test-mode" --acr-name myacr --min-score 9
""", tmp_path)
        content = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        assert "=== defender-local-actions run ===" in content
        assert "script:     unit-test" in content
        assert "mode:       test-mode" in content
        assert "--acr-name myacr" in content
        assert re.search(r"timestamp:\s+\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", content)

    def test_two_runs_get_distinct_files(self, tmp_path: Path) -> None:
        for i in range(2):
            _run_bash_script(f"""
source "{REPO_ROOT}/lib/logging.sh"
init_logging "run-{i}" "test"
""", tmp_path)
        assert len(list((tmp_path / "logs").glob("run-*.log"))) == 2


# ---------------------------------------------------------------------------
# log_* helpers: format and terminal-always semantics
# ---------------------------------------------------------------------------

class TestLogHelpers:
    def test_log_info_hits_stderr_and_file(self, tmp_path: Path) -> None:
        r = _run_bash_script(f"""
source "{REPO_ROOT}/lib/logging.sh"
init_logging "test" "mode"
log_info "hello world 123"
""", tmp_path)
        assert r.returncode == 0
        # Terminal (stderr) shows the line
        assert "INFO" in r.stderr and "hello world 123" in r.stderr
        # And it's in the file
        content = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        assert re.search(r"\[\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\] INFO\s+hello world 123",
                         content)

    def test_log_warn_and_error_labelled(self, tmp_path: Path) -> None:
        _run_bash_script(f"""
source "{REPO_ROOT}/lib/logging.sh"
init_logging "test" "mode"
log_warn "watch out"
log_error "boom"
""", tmp_path)
        content = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        assert re.search(r"WARN\s+watch out", content)
        assert re.search(r"ERROR\s+boom", content)

    def test_log_without_init_still_prints_to_stderr(self, tmp_path: Path) -> None:
        """If init_logging was never called, log_* must still work on terminal."""
        r = _run_bash_script(f"""
source "{REPO_ROOT}/lib/logging.sh"
log_info "no init here"
""", tmp_path)
        assert r.returncode == 0
        assert "no init here" in r.stderr
        assert not (tmp_path / "logs").exists()


# ---------------------------------------------------------------------------
# Best-effort: log_* never crashes the caller when the file becomes unusable
# ---------------------------------------------------------------------------

class TestBestEffort:
    def test_log_survives_file_removed_at_runtime(self, tmp_path: Path) -> None:
        """A common failure mode: someone deletes logs/ mid-run.
        log_* must swallow the write error and keep the script alive."""
        r = _run_bash_script(f"""
source "{REPO_ROOT}/lib/logging.sh"
init_logging "test" "mode"
log_info "line one"
rm -f "$LOG_FILE"
chmod -w "{tmp_path}/logs" 2>/dev/null || true
log_info "line two after tampering"
log_warn "warn after tampering"
chmod +w "{tmp_path}/logs" 2>/dev/null || true
echo "still alive"
""", tmp_path)
        assert r.returncode == 0, f"log_* killed the shell: {r.stderr}"
        assert "still alive" in r.stdout
        assert "line two after tampering" in r.stderr
        assert "warn after tampering" in r.stderr

    def test_init_degrades_when_logs_dir_not_writable(self, tmp_path: Path) -> None:
        blocker = tmp_path / "notadir"
        blocker.write_text("not a dir\n")
        r = _run_bash_script(f"""
export LOG_DIR="{blocker}/logs"
source "{REPO_ROOT}/lib/logging.sh"
init_logging "test" "mode"
log_info "after init"
echo "still alive"
""", tmp_path)
        assert r.returncode == 0
        assert "still alive" in r.stdout
        assert "could not create" in r.stderr.lower()

    def test_engine_independent_of_logging(self, tmp_path: Path) -> None:
        """Even with file logging disabled, defender.sh completes normally."""
        bin_dir = tmp_path / "bin"
        _make_fake_az(bin_dir)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        # Force file logging to fail
        blocker = tmp_path / "block"
        blocker.write_text("blocking\n")
        env["LOG_DIR"] = str(blocker / "impossible")

        result = subprocess.run(
            [str(DEFENDER), "--acr-name", "myacr", "--min-score", "9"],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        assert result.returncode == 0, result.stderr
        assert "Processing complete" in result.stdout
        assert "could not create" in result.stderr.lower()
        assert not (tmp_path / "logs").exists()


# ---------------------------------------------------------------------------
# Secret scrubbing
# ---------------------------------------------------------------------------

class TestSecretScrubbing:
    def test_token_flag_value_redacted(self, tmp_path: Path) -> None:
        _run_bash_script(f"""
source "{REPO_ROOT}/lib/logging.sh"
init_logging "test" "mode" --token SUPER-SECRET-XYZ --min-score 9
""", tmp_path)
        content = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        assert "<redacted>" in content
        assert "SUPER-SECRET-XYZ" not in content
        assert "--token" in content
        assert "--min-score 9" in content

    def test_multiple_secret_flag_names_scrubbed(self, tmp_path: Path) -> None:
        _run_bash_script(f"""
source "{REPO_ROOT}/lib/logging.sh"
init_logging "test" "mode" --password hunter2 --secret abc --api-key xyz
""", tmp_path)
        content = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        for leak in ("hunter2", "abc", "xyz"):
            assert leak not in content


# ---------------------------------------------------------------------------
# End-to-end critical events in defender.sh + check_ocp.sh
# ---------------------------------------------------------------------------

class TestDefenderCriticalEvents:
    def test_start_and_end_events_recorded(self, tmp_path: Path) -> None:
        bin_dir = tmp_path / "bin"
        _make_fake_az(bin_dir)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        subprocess.run(
            [str(DEFENDER), "--acr-name", "myacr", "--min-score", "9"],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        content = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        assert re.search(r"INFO\s+start acr=myacr mode=report-only", content)
        # Post-P2 the end-line uses digests=<n> (per (repo, digest) pair count);
        # empty enumerate result yields digests=0.
        assert re.search(
            r"INFO\s+end total_processed=0 digests=0 report_file=", content,
        )

    def test_defender_exit_trap_not_broken_by_logging(self, tmp_path: Path) -> None:
        """No leftover *.csv.tmp.* files means the EXIT trap ran cleanly.
        Since logging.sh doesn't touch traps, defender.sh's own trap
        remains fully in charge — this test protects that invariant."""
        bin_dir = tmp_path / "bin"
        _make_fake_az(bin_dir)
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        subprocess.run(
            [str(DEFENDER), "--acr-name", "myacr", "--min-score", "9"],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        assert not list(tmp_path.glob("*.csv.tmp.*"))


class TestCheckOcpCriticalEvents:
    def test_coverage_complete_logged(self, tmp_path: Path) -> None:
        bin_dir = tmp_path / "bin"
        _make_fake_oc(bin_dir, "ok")
        vulns = _empty_vulns_csv(tmp_path / "vulns.csv")
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        subprocess.run(
            [str(CHECK_OCP), str(vulns), str(tmp_path / "out.csv")],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        content = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        assert re.search(r"INFO\s+COVERAGE COMPLETE", content)
        assert re.search(r"INFO\s+end output_file=.*coverage_exit=0", content)

    def test_rbac_error_logged_per_namespace(self, tmp_path: Path) -> None:
        bin_dir = tmp_path / "bin"
        _make_fake_oc(bin_dir, "rbac")
        vulns = _empty_vulns_csv(tmp_path / "vulns.csv")
        env = os.environ.copy()
        env["PATH"] = f"{bin_dir}:{env['PATH']}"
        result = subprocess.run(
            [str(CHECK_OCP), str(vulns), str(tmp_path / "out.csv")],
            cwd=tmp_path, env=env, capture_output=True, text=True, check=False,
        )
        assert result.returncode == 3
        content = next((tmp_path / "logs").glob("run-*.log")).read_text(encoding="utf-8")
        assert re.search(r"WARN\s+namespace=prd-locked RBAC_ERR", content)
        assert re.search(r"WARN\s+COVERAGE PARTIAL", content)
