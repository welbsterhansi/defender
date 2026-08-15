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


class TestParseRepoList:
    """
    Contract: `parse_repo_list` splits comma-separated input into one entry
    per line, trims whitespace, drops empty entries, and de-duplicates keeping
    first occurrence. Pure — no side effects, no trailing newline gremlins.
    """

    def test_simple_list(self) -> None:
        out = _bash_call("parse_repo_list", "a,b,c")
        assert out.strip().split("\n") == ["a", "b", "c"]

    def test_trims_whitespace(self) -> None:
        out = _bash_call("parse_repo_list", "  a , b ,c  ")
        assert out.strip().split("\n") == ["a", "b", "c"]

    def test_dedups_preserving_first(self) -> None:
        out = _bash_call("parse_repo_list", "a,b,a,c,b")
        assert out.strip().split("\n") == ["a", "b", "c"]

    def test_drops_empty_entries(self) -> None:
        out = _bash_call("parse_repo_list", "a,,b,,,c,")
        assert out.strip().split("\n") == ["a", "b", "c"]

    def test_single_entry(self) -> None:
        out = _bash_call("parse_repo_list", "only")
        assert out.strip() == "only"

    def test_empty_input(self) -> None:
        # Empty string yields empty output (no rows). Callers must check
        # for this to distinguish "no filter" from "filter with 0 entries".
        assert _bash_call("parse_repo_list", "").strip() == ""


class TestBuildReposFilterExpr:
    """
    Contract: emits `prop contains "r1" or prop contains "r2"` style KQL
    string. Empty when no repos are passed. Property name is used verbatim
    (caller is responsible for using the KQL-appropriate path).
    """

    def test_single_repo(self) -> None:
        out = _bash_call_multi("build_repos_filter_expr", "p.name", "app")
        assert out == 'p.name contains "app"'

    def test_two_repos_joined_with_or(self) -> None:
        out = _bash_call_multi("build_repos_filter_expr",
                               "p.name", "app", "payments")
        assert out == 'p.name contains "app" or p.name contains "payments"'

    def test_three_repos(self) -> None:
        out = _bash_call_multi("build_repos_filter_expr",
                               "p.name", "a", "b", "c")
        assert out == ('p.name contains "a" or '
                       'p.name contains "b" or '
                       'p.name contains "c"')

    def test_empty_repos_yields_empty(self) -> None:
        out = _bash_call_multi("build_repos_filter_expr", "p.name")
        assert out == ""
