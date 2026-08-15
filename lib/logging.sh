# shellcheck shell=bash
# ---------------------------------------------------------------------------
# lib/logging.sh — best-effort structured logging for critical events.
#
# Design principle: the engine (defender.sh / check_ocp.sh) never fails
# because of the logger. Nothing here does `exec` or reroutes file
# descriptors globally; every file write is guarded with `|| true`. If
# `logs/` can't be created or the file becomes unwritable at runtime,
# `log_*` calls skip the file write and keep writing to the terminal.
# Logging is evidence, not truth — it must not gate the scan.
#
# Usage:
#
#   # shellcheck source=lib/logging.sh
#   source "$(dirname "$0")/lib/logging.sh"
#   init_logging <script-name> <mode> [<safe-args...>]
#   log_info  "start acr=$ACR_NAME mode=$MODE"
#   log_warn  "namespace $ns: RBAC error"
#   log_error "az graph query failed on page $n after 3 attempts"
#
# Format of every log line:
#   [YYYY-MM-DDTHH:MM:SSZ] LEVEL  message
#
# Scrubbing:
#   Callers must NOT pass credentials as positional args.
#   init_logging scrubs the value that FOLLOWS any argument whose NAME
#   contains `token`, `password`, `secret`, or `key` (case-insensitive) —
#   a guard-rail against accidents, not a security boundary.
# ---------------------------------------------------------------------------

# Empty when file logging is disabled (env didn't allow it or init_logging
# was never called). log_* helpers treat empty as "terminal only".
export LOG_FILE=""

_ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# ---------------------------------------------------------------------------
# _emit LEVEL MSG — the single write path. Always writes to stderr; if
# LOG_FILE is set and writable, appends the same line to the file. Every
# file operation is guarded with `|| true` so a failed write never
# propagates back to the caller under `set -euo pipefail`.
# ---------------------------------------------------------------------------
_emit() {
    local level="$1"; shift
    local line
    printf -v line '[%s] %-5s %s' "$(_ts)" "$level" "$*"
    printf '%s\n' "$line" >&2
    if [ -n "${LOG_FILE:-}" ]; then
        printf '%s\n' "$line" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

log_info()  { _emit "INFO"  "$*"; }
log_warn()  { _emit "WARN"  "$*"; }
log_error() { _emit "ERROR" "$*"; }

# ---------------------------------------------------------------------------
# _scrub_args_for_log — format argv as a single log line, replacing the
# value that follows any secret-looking flag with <redacted>.
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
# init_logging — try to open a file for later log_* calls. Never aborts.
# On any failure (mkdir, first write), LOG_FILE stays empty and log_*
# keeps working in terminal-only mode. The caller does not need to check
# the return code.
# ---------------------------------------------------------------------------
init_logging() {
    local script_name="${1:-unknown}"; shift || true
    local mode="${1:-unknown}";        shift || true

    local run_dir="${LOG_DIR:-logs}"
    if ! mkdir -p "$run_dir" 2>/dev/null; then
        log_warn "logging: could not create '$run_dir'; file logging disabled"
        LOG_FILE=""
        return 0
    fi

    # `$$` (parent shell pid) makes the name collision-safe even when two
    # runs land in the same second (parallel CI, quick retries).
    local ts
    ts=$(date -u +%Y%m%d-%H%M%S)
    local candidate="${run_dir}/run-${ts}-$$.log"

    # Prove the file is writable by emitting the header. If any write
    # fails, disable file logging and continue on terminal only.
    local args_scrubbed
    args_scrubbed=$(_scrub_args_for_log "$@")
    if ! {
        printf '=== defender-local-actions run ===\n'
        printf 'timestamp:  %s\n' "$(_ts)"
        printf 'script:     %s\n' "$script_name"
        printf 'mode:       %s\n' "$mode"
        printf 'args:       %s\n' "${args_scrubbed:-<none>}"
        printf 'log_file:   %s\n' "$candidate"
        printf 'pid:        %s\n' "$$"
        printf '==================================\n'
    } >> "$candidate" 2>/dev/null; then
        log_warn "logging: could not write to '$candidate'; file logging disabled"
        LOG_FILE=""
        return 0
    fi

    LOG_FILE="$candidate"
    log_info "logging started: $LOG_FILE"
}
