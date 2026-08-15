"""
Runtime tests for pure-function helpers inside defender.sh.

Same rationale as tests/test_shell_jq_runtime.py: `bash -n` catches syntax
errors but not behavioral bugs. These tests source the script's function
region and call each helper against known inputs.

We source only the helper region (top of the file, before the main flow)
to avoid triggering argument parsing or Azure calls.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFENDER_SH = REPO_ROOT / "defender.sh"


pytestmark = pytest.mark.skipif(
    shutil.which("bash") is None, reason="bash not available"
)


def _bash_call(fn: str, arg: str) -> str:
    """Source defender.sh's helper region and call `fn "$arg"`, return stdout."""
    # Extract the top of the file up to (but not including) the `usage()`
    # function — that's where the pure helpers live and it stops before any
    # side-effect code runs.
    text = DEFENDER_SH.read_text(encoding="utf-8")
    marker = "# Function to display usage"
    assert marker in text, "expected marker not found in defender.sh"
    helpers_only = text.split(marker, 1)[0]

    result = subprocess.run(
        ["bash", "-c", f"{helpers_only}\n{fn} \"$1\"", "_", arg],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, (
        f"bash exited {result.returncode}\nstderr:\n{result.stderr}"
    )
    return result.stdout


class TestRepoToDashedPath:
    """
    Contract: `repo_to_dashed_path` mirrors the Defender KQL convention that
    stores repository paths inside `resourceDetails.Id` with `/` replaced by
    `-`. Must be pure (no trailing newline, no shell substitutions).
    """

    def test_single_segment(self) -> None:
        assert _bash_call("repo_to_dashed_path", "backend") == "backend"

    def test_two_segments(self) -> None:
        assert _bash_call("repo_to_dashed_path",
                          "base-images/ubi9-openjdk17") == "base-images-ubi9-openjdk17"

    def test_nested_path(self) -> None:
        assert _bash_call("repo_to_dashed_path",
                          "team/service/component") == "team-service-component"

    def test_empty_input(self) -> None:
        assert _bash_call("repo_to_dashed_path", "") == ""

    def test_no_trailing_newline(self) -> None:
        """`tr` via printf must not add a newline — used inside KQL strings."""
        out = _bash_call("repo_to_dashed_path", "a/b")
        assert out == "a-b", f"unexpected trailing chars: {out!r}"

    def test_preserves_dashes_and_dots(self) -> None:
        assert _bash_call("repo_to_dashed_path",
                          "a.b-c/d.e-f") == "a.b-c-d.e-f"


def _bash_call_multi(fn: str, *args: str) -> str:
    """Same as _bash_call but forwards multiple positional args."""
    text = DEFENDER_SH.read_text(encoding="utf-8")
    marker = "# Function to display usage"
    helpers_only = text.split(marker, 1)[0]
    quoted = " ".join(f'"$"{i+1}' for i in range(len(args)))
    quoted = " ".join(f'"${{{i+1}}}"' for i in range(len(args)))
    result = subprocess.run(
        ["bash", "-c", f'{helpers_only}\n{fn} {quoted}', "_", *args],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, (
        f"bash exited {result.returncode}\nstderr:\n{result.stderr}"
    )
    return result.stdout


def _bash_call_expect_fail(fn: str, arg: str) -> tuple[int, str]:
    """Run helper expecting non-zero exit; return (rc, stderr)."""
    text = DEFENDER_SH.read_text(encoding="utf-8")
    marker = "# Function to display usage"
    helpers_only = text.split(marker, 1)[0]
    result = subprocess.run(
        ["bash", "-c", f"{helpers_only}\n{fn} \"$1\"", "_", arg],
        capture_output=True, text=True, check=False,
    )
    return result.returncode, result.stderr


class TestParseRepoList:
    """
    Contract (task #38): --repositories is a CONTROLLED list.
    parse_repo_list must:
      - trim whitespace on each entry
      - REJECT empty entries (exit 2, stderr message)
      - REJECT duplicates (exit 2, stderr message)
      - REJECT fully empty input (exit 2)
      - accept slashed repos like `team/app` unchanged
    """

    def test_simple_list(self) -> None:
        out = _bash_call("parse_repo_list", "a,b,c")
        assert out.strip().split("\n") == ["a", "b", "c"]

    def test_trims_whitespace(self) -> None:
        out = _bash_call("parse_repo_list", "  a , b ,c  ")
        assert out.strip().split("\n") == ["a", "b", "c"]

    def test_slashed_repo_ok(self) -> None:
        out = _bash_call("parse_repo_list", "team/app,payments")
        assert out.strip().split("\n") == ["team/app", "payments"]

    def test_single_entry(self) -> None:
        out = _bash_call("parse_repo_list", "only")
        assert out.strip() == "only"

    def test_empty_middle_entry_fails(self) -> None:
        rc, err = _bash_call_expect_fail("parse_repo_list", "app,,payments")
        assert rc == 2
        assert "empty entry" in err.lower()

    def test_trailing_comma_fails(self) -> None:
        rc, err = _bash_call_expect_fail("parse_repo_list", "app,payments,")
        assert rc == 2
        assert "empty entry" in err.lower()

    def test_duplicate_entry_fails(self) -> None:
        rc, err = _bash_call_expect_fail(
            "parse_repo_list", "app,payments,app"
        )
        assert rc == 2
        assert "duplicate" in err.lower()
        assert "app" in err

    def test_empty_input_fails(self) -> None:
        rc, err = _bash_call_expect_fail("parse_repo_list", "")
        assert rc == 2

    def test_whitespace_only_input_fails(self) -> None:
        # "   " with no delimiter — a single field that trims to empty.
        rc, _ = _bash_call_expect_fail("parse_repo_list", "   ")
        assert rc == 2


class TestBuildReposInExpr:
    """
    Contract: emit KQL `prop in ("r1", "r2")` — exact-match list literal.
    Empty when no repos are passed.
    """

    def test_single_repo(self) -> None:
        out = _bash_call_multi("build_repos_in_expr", "p.name", "app")
        assert out == 'p.name in ("app")'

    def test_multi_repos(self) -> None:
        out = _bash_call_multi("build_repos_in_expr",
                               "p.name", "app", "payments")
        assert out == 'p.name in ("app", "payments")'

    def test_empty_yields_empty(self) -> None:
        out = _bash_call_multi("build_repos_in_expr", "p.name")
        assert out == ""


class TestBuildReposIdAnchorExpr:
    """
    Contract: emit anchored `contains "repositories-<dashed>-images-"`
    clauses. The `repositories-…-images-` bracketing is the exact-match
    anchor for Leg B; without it, `app` would substring-match `app-backend`.
    """

    def test_single_repo(self) -> None:
        out = _bash_call_multi("build_repos_id_anchor_expr", "p.Id", "app")
        assert out == 'p.Id contains "repositories-app-images-"'

    def test_multi_repos(self) -> None:
        out = _bash_call_multi("build_repos_id_anchor_expr",
                               "p.Id", "app", "payments")
        assert out == (
            'p.Id contains "repositories-app-images-" or '
            'p.Id contains "repositories-payments-images-"'
        )

    def test_slashed_repo_gets_dashed(self) -> None:
        out = _bash_call_multi("build_repos_id_anchor_expr",
                               "p.Id", "team/app")
        # Leg B uses the dashed path — `team/app` → `team-app`.
        assert 'contains "repositories-team-app-images-"' in out

    def test_empty_yields_empty(self) -> None:
        out = _bash_call_multi("build_repos_id_anchor_expr", "p.Id")
        assert out == ""
