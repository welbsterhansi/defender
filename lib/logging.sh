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
# After init_logging, everything the script writes to stdout or stderr is
# also appended to $LOG_FILE. The operator still sees output live; nothing
# is silenced. Path is deterministic (`logs/run-YYYYMMDD-HHMMSS.log`, UTC)
# so CI/pipeline steps can collect it as an artifact.
#
# Scrubbing:
#   Callers must NOT pass credentials / tokens as positional args.
#   init_logging scrubs the VALUE that follows any argument whose NAME
#   contains `token`, `password`, `secret`, or `key` (case-insensitive) —
#   guard-rail against accidental leaks, not a security boundary.
# ---------------------------------------------------------------------------

# Exported so the caller and downstream tools can reference the path.
export LOG_FILE=""

# Format an argv into a single log-safe line, redacting values that follow
# a flag name whose text hints at a secret. Idempotent; safe for empty argv.
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
    # trim leading space
    printf '%s' "${out# }"
}

init_logging() {
    local script_name="${1:-unknown}"; shift || true
    local mode="${1:-unknown}";        shift || true

    local run_dir="${LOG_DIR:-logs}"
    mkdir -p "$run_dir" 2>/dev/null || {
        # Filesystem read-only or permission denied — proceed WITHOUT file
        # logging but keep stdout/stderr as-is. Never break the operator.
        echo "[logging] WARN: could not create '$run_dir' — logs will not be persisted" >&2
        return 0
    }

    local ts
    ts=$(date -u +%Y%m%d-%H%M%S)
    LOG_FILE="${run_dir}/run-${ts}.log"

    # Redirect both streams through tee so the file gets everything and the
    # terminal still shows realtime output. stderr keeps flowing as stderr
    # on the terminal (colours/redirection preserved).
    exec > >(tee -a "$LOG_FILE") 2> >(tee -a "$LOG_FILE" >&2)

    # Give the tee subprocesses a beat to flush at exit — process
    # substitution is not wait()ed by the parent shell, so without this
    # the last handful of bytes can be lost.
    trap 'sync; sleep 0.05' EXIT

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
