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
