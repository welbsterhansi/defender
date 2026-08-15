"""
Runtime validation of the jq expressions embedded in the shell scripts.

Rationale: `bash -n` catches syntax errors in the shell wrapper but happily
compiles a script whose *jq* is broken — it doesn't know jq syntax. A quoting
mistake (e.g. `\\'` where a closing `'` should be) only surfaces when the pipe
actually runs. These tests extract each jq block and feed it representative
input, so a future regression fails fast without needing a live cluster.

Skip cleanly if `jq` is not installed.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
CHECK_OCP = REPO_ROOT / "check_ocp.sh"


pytestmark = pytest.mark.skipif(
    shutil.which("jq") is None, reason="jq not installed"
)


def _run_jq(program: str, stdin: str, args: list[str] | None = None) -> str:
    """Run `jq <args> <program>` with the given stdin. Fails on non-zero exit."""
    result = subprocess.run(
        ["jq", *(args or []), program],
        input=stdin, capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, (
        f"jq exited {result.returncode}\n"
        f"program:\n{program}\n"
        f"stderr:\n{result.stderr}"
    )
    return result.stdout


def _extract_check_ocp_jq() -> str:
    """Pull the jq program from check_ocp.sh.

    Since the hardening refactor (task #28), the program lives in a bash
    variable `JQ_POD_EXTRACT='...'` so we look for that assignment.
    """
    text = CHECK_OCP.read_text(encoding="utf-8")
    match = re.search(
        r"JQ_POD_EXTRACT='(.*?)'\s*\n",
        text, re.DOTALL,
    )
    assert match, "could not locate JQ_POD_EXTRACT in check_ocp.sh"
    return match.group(1)


def test_check_ocp_jq_closing_quote_is_clean() -> None:
    """Regex-level guard: no `\\'` sequence in the jq block region.

    The Python regex substitution used in a prior fix accidentally consumed
    the closing single quote and left `\\'` behind. `bash -n` passed but the
    pipe blew up at runtime with jq exit 3. This test catches the pattern
    directly against the file.
    """
    text = CHECK_OCP.read_text(encoding="utf-8")
    assert "\\'" not in text, (
        "Found `\\'` in check_ocp.sh — likely a corrupted jq closing quote. "
        "Should be a bare `'` to close the single-quoted jq program."
    )


def test_check_ocp_jq_executes_against_realistic_pod_json() -> None:
    """The extracted jq must accept `oc get pods -o json` output shapes."""
    program = _extract_check_ocp_jq()

    fake_oc_output = {
        "items": [
            # Deployment via ReplicaSet
            {
                "metadata": {
                    "namespace": "prd-app",
                    "name": "backend-abc",
                    "ownerReferences": [
                        {"kind": "ReplicaSet", "name": "backend-77f"}
                    ],
                },
                "status": {
                    "containerStatuses": [
                        {"imageID": "docker-pullable://reg/backend@sha256:aaa"}
                    ],
                },
            },
            # StatefulSet with init container
            {
                "metadata": {
                    "namespace": "prd-db",
                    "name": "pg-0",
                    "ownerReferences": [
                        {"kind": "StatefulSet", "name": "pg"}
                    ],
                },
                "status": {
                    "containerStatuses": [
                        {"imageID": "docker-pullable://reg/pg@sha256:bbb"}
                    ],
                    "initContainerStatuses": [
                        {"imageID": "docker-pullable://reg/init@sha256:ccc"}
                    ],
                },
            },
            # Bare pod: no ownerReferences → empty owner fields
            {
                "metadata": {"namespace": "prd-legacy", "name": "one-off"},
                "status": {
                    "containerStatuses": [
                        {"imageID": "docker-pullable://old/j@sha256:ddd"}
                    ],
                },
            },
            # Pending pod: no containerStatuses → empty image_ids
            {
                "metadata": {
                    "namespace": "prd-app",
                    "name": "pending",
                    "ownerReferences": [
                        {"kind": "ReplicaSet", "name": "pending-rs"}
                    ],
                },
                "status": {},
            },
        ]
    }
    stdout = _run_jq(program, json.dumps(fake_oc_output), args=["-r"])
    lines = stdout.strip("\n").split("\n")
    assert len(lines) == 4, f"expected 4 rows, got {len(lines)}: {lines!r}"

    # Records separated by ASCII 0x1F (US), per the script's design
    for line in lines:
        fields = line.split("\x1f")
        assert len(fields) == 5, (
            f"expected 5 US-separated fields, got {len(fields)}: {fields!r}"
        )

    # Spot-check individual rows
    def parse(idx: int) -> tuple[str, ...]:
        return tuple(lines[idx].split("\x1f"))

    ns, pod, kind, name, images = parse(0)
    assert ns == "prd-app" and pod == "backend-abc"
    assert kind == "ReplicaSet" and name == "backend-77f"
    assert "sha256:aaa" in images

    _, pod2, _, _, images2 = parse(1)
    assert pod2 == "pg-0"
    assert "sha256:bbb" in images2 and "sha256:ccc" in images2

    ns3, pod3, kind3, name3, images3 = parse(2)
    assert ns3 == "prd-legacy" and pod3 == "one-off"
    assert kind3 == "" and name3 == "", "bare pod must have empty owner fields"
    assert "sha256:ddd" in images3

    _, pod4, _, _, images4 = parse(3)
    assert pod4 == "pending"
    assert images4 == "", "pending pod (no containerStatuses) must produce empty images"


def test_check_ocp_jq_handles_empty_items() -> None:
    """No pods → empty output, no crash."""
    program = _extract_check_ocp_jq()
    stdout = _run_jq(program, '{"items":[]}', args=["-r"])
    assert stdout == "" or stdout == "\n"
