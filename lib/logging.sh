# shellcheck shell=bash
# ---------------------------------------------------------------------------
# lib/logging.sh — persist all script output to a timestamped log file
# while preserving realtime output on the terminal.
#
# Usage from a caller script:
#
#   # shellcheck source=lib/logging.sh
#   source "$(dirname "$0")/lib/logging.sh"
#   init_logging <script-name> <mode> [<safe-args...>]
#
# Behaviors:
#   - `logs/` is created on demand
#   - name: `logs/run-YYYYMMDD-HHMMSS-<pid>.log` (UTC + pid = collision-safe
#     even under parallel CI)
#   - stdout+stderr are tee'd into the file; the operator still sees output
#     live on the terminal; nothing is silenced
#   - if the environment doesn't support `/dev/fd` + tee (locked-down
#     containers, seccomp, POSIX-only sh emulation), a WARN is printed and
#     the caller runs WITHOUT file logging — logging never breaks the run
#   - the EXIT trap used to flush tee is COMPOSED with any pre-existing
#     trap via `_add_exit_trap`, so callers keep their cleanup handlers
#
# Scrubbing:
#   Callers must NOT pass credentials / tokens as positional args.
#   init_logging scrubs the VALUE that follows any argument whose NAME
#   contains `token`, `password`, `secret`, or `key` (case-insensitive) —
#   guard-rail against accidental leaks, not a security boundary.
# ---------------------------------------------------------------------------

# Exported so the caller and downstream tools can reference the path.
# Empty string means file logging is disabled (env didn't support it).
export LOG_FILE=""

# ---------------------------------------------------------------------------
# Append a command to the EXIT trap without dropping whatever the caller
# (or a previously-loaded lib) already registered. Handles the three shapes
# `trap -p EXIT` can return: no trap set, single-quoted body, or empty.
# ---------------------------------------------------------------------------
_add_exit_trap() {
    local new_cmd="$1"
    local existing
    # `trap -p EXIT` prints: `trap -- 'cmd' EXIT`  (or nothing if unset)
    existing=$(trap -p EXIT 2>/dev/null | sed -n "s/^trap -- '\(.*\)' EXIT\$/\1/p")
    # Traps are expanded at trigger time; the composition below is on
    # purpose (embedding the caller-supplied command into the trap body).
    # shellcheck disable=SC2064
    if [ -n "$existing" ]; then
        trap "${existing}; ${new_cmd}" EXIT
    else
        trap "$new_cmd" EXIT
    fi
}

# ---------------------------------------------------------------------------
# Format an argv into a single log-safe line, redacting values that follow
# a flag name whose text hints at a secret. Idempotent; safe for empty argv.
# ---------------------------------------------------------------------------
_scrub_args_for_log() {
    local prev="" out=""
    for tok in "$@"; do
        if [[ "$prev" =~ [Tt]oken|[Pp]assword|[Ss]ecret|[Kk]ey ]]; then
            out+=" <redacted>"
        else
            out+=" $tok"
        fi
        prev="$tok"
    done
    printf '%s' "${out# }"
}

# ---------------------------------------------------------------------------
# Probe whether this shell can actually do the redirect we need. A subshell
# is used so a probe failure does not affect the parent shell's stdout/stderr.
# Returns 0 = supported; 1 = not supported (caller should degrade).
# ---------------------------------------------------------------------------
_logging_env_supports_tee() {
    # Prereqs first — cheap sniff.
    [ -d /dev/fd ]                           || return 1
    command -v tee >/dev/null 2>&1           || return 1
    # Actual functional probe: process substitution + a tiny tee. Everything
    # runs inside a subshell so failure never touches the parent's fds.
    ( : > >(cat > /dev/null); wait ) 2>/dev/null
}

# ---------------------------------------------------------------------------
# The public entry point.
# ---------------------------------------------------------------------------
init_logging() {
    local script_name="${1:-unknown}"; shift || true
    local mode="${1:-unknown}";        shift || true

    local run_dir="${LOG_DIR:-logs}"
    if ! mkdir -p "$run_dir" 2>/dev/null; then
        echo "[logging] WARN: could not create '$run_dir' — logs will not be persisted" >&2
        LOG_FILE=""
        return 0
    fi

    if ! _logging_env_supports_tee; then
        echo "[logging] WARN: process substitution or tee not usable here — logs will not be persisted" >&2
        LOG_FILE=""
        return 0
    fi

    # `$$` (parent shell pid) makes the name collision-safe even when two
    # runs land in the same second (parallel CI, quick retries).
    local ts
    ts=$(date -u +%Y%m%d-%H%M%S)
    LOG_FILE="${run_dir}/run-${ts}-$$.log"

    # Redirect both streams through tee. The file gets everything; stderr
    # keeps flowing as stderr on the terminal (colours/redirection
    # preserved).
    exec > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)

    # Give the tee subprocesses a beat to flush at exit — process
    # substitution is not wait()ed by the parent shell, so without this
    # the last handful of bytes can be lost. Compose (don't replace) any
    # existing EXIT trap the caller may already have set.
    _add_exit_trap 'sync; sleep 0.05'

    # Header — first thing in the file, easy to grep in CI dashboards.
    local args_scrubbed
    args_scrubbed=$(_scrub_args_for_log "$@")
    {
        printf '=== defender-local-actions run ===\n'
        printf 'timestamp:  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        printf 'script:     %s\n' "$script_name"
        printf 'mode:       %s\n' "$mode"
        printf 'args:       %s\n' "${args_scrubbed:-<none>}"
        printf 'log_file:   %s\n' "$LOG_FILE"
        printf 'pid:        %s\n' "$$"
        printf '==================================\n'
    }
}
