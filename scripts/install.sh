#!/usr/bin/env bash
#
# Polaris easy-install bootstrapper (issue #209).
#
# Purpose
#   Take a fresh Linux host from zero to a running Polaris stack with the
#   smallest possible operator effort. The script is idempotent — running
#   it twice on the same host is safe; pre-existing files are preserved
#   unless POLARIS_FORCE=1 is set.
#
# Usage (one of these two paths)
#
#   1. From a checked-out repo:
#        ./scripts/install.sh
#
#   2. Piped from raw.githubusercontent.com:
#        curl -sSL https://raw.githubusercontent.com/dollspace-gay/polaris/main/scripts/install.sh | bash
#
#   In path #2 stdin is the curl pipe (no tty available); the script
#   detects that and runs `polaris-setup --non-interactive`, which
#   requires POLARIS_HOSTNAME to be set in the environment.
#
# Environment
#   POLARIS_HOSTNAME       Public DNS hostname (required when piped).
#   POLARIS_NONINTERACTIVE Force non-interactive mode (0/1; default: auto-detect).
#   POLARIS_FORCE          Pass --force to polaris-setup (0/1; default: 0).
#   POLARIS_INSTALL_DIR    Where to clone/operate when not in a repo
#                          (default: ./polaris).
#   POLARIS_VERSION        Release tag of polaris-setup to fetch when the
#                          binary isn't already on PATH (default: latest).
#
# Exit codes
#   0  Success — setup ran, next-command printed.
#   1  Missing prerequisite (docker / docker compose v2 / curl / tar).
#   2  Setup binary failed (passed through from polaris-setup).
#   3  Internal error (network failure, broken repo clone, etc.).

set -o errexit
set -o nounset
set -o pipefail
IFS=$'\n\t'

# ── Constants ────────────────────────────────────────────────────────────
readonly REPO_OWNER="dollspace-gay"
readonly REPO_NAME="polaris"
readonly REPO_URL="https://github.com/${REPO_OWNER}/${REPO_NAME}.git"
readonly RAW_URL="https://raw.githubusercontent.com/${REPO_OWNER}/${REPO_NAME}/main"
# The GitHub release-asset naming convention. The publish-image
# workflow does NOT yet upload binary assets — this fetch path is
# the forward-compatible hook for when it does. Until then, the
# script falls back to building from source via cargo when --build
# is supplied. See `fetch_setup_binary` below.
readonly SETUP_BIN_NAME="polaris-setup"

readonly EXIT_PREREQ_MISSING=1
readonly EXIT_SETUP_FAILED=2
readonly EXIT_INTERNAL=3

# ── Logging helpers (all to stderr; stdout reserved for data) ────────────
log() { printf '==> %s\n' "$*" >&2; }
warn() { printf 'warn: %s\n' "$*" >&2; }
die() {
    printf 'error: %s\n' "$*" >&2
    exit "${EXIT_INTERNAL}"
}

# Exit trap: surface the line that failed. The trap fires on any
# non-zero return that errexit catches, including failures inside
# pipelines (because of pipefail).
trap 'rc=$?; if [[ ${rc} -ne 0 ]]; then printf "error: install.sh failed at line %d (exit %d)\n" "${LINENO}" "${rc}" >&2; fi' EXIT

# ── Tiny CLI ─────────────────────────────────────────────────────────────
usage() {
    cat <<'USAGE'
Polaris easy-install bootstrapper.

Usage: install.sh [--help] [--dry-run]

Options:
  --help, -h    Show this message and exit.
  --dry-run     Print the steps the script would run without
                executing them.

Environment:
  POLARIS_HOSTNAME       Public DNS hostname (required when piped).
  POLARIS_NONINTERACTIVE Force non-interactive mode (0/1).
  POLARIS_FORCE          Pass --force to polaris-setup (0/1).
  POLARIS_INSTALL_DIR    Directory to clone into (default: ./polaris).
  POLARIS_VERSION        polaris-setup release tag (default: latest).
USAGE
}

DRY_RUN=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h)
            usage
            exit 0
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        *)
            warn "unknown argument: $1"
            usage
            exit "${EXIT_PREREQ_MISSING}"
            ;;
    esac
done
readonly DRY_RUN

# `run` echoes (in --dry-run) or executes the given command. We
# pass the command through "$@" so quoting survives — never use
# `eval` here.
run() {
    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '+ %s\n' "$*" >&2
    else
        "$@"
    fi
}

# ── Step 1: prerequisites ────────────────────────────────────────────────

require_cmd() {
    local cmd="$1"
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        printf 'error: %s is required but not installed.\n' "${cmd}" >&2
        printf '       install %s and re-run scripts/install.sh.\n' "${cmd}" >&2
        exit "${EXIT_PREREQ_MISSING}"
    fi
}

check_prereqs() {
    log "Checking prerequisites"
    require_cmd docker
    require_cmd curl
    require_cmd tar

    # Docker Compose v2 is invoked as `docker compose ...` (no
    # hyphen). The legacy `docker-compose` binary is not supported.
    if ! docker compose version >/dev/null 2>&1; then
        printf 'error: Docker Compose v2 is required (invoked as `docker compose`).\n' >&2
        printf '       See https://docs.docker.com/compose/install/ for installation.\n' >&2
        exit "${EXIT_PREREQ_MISSING}"
    fi
}

# ── Step 2: determine where we are ───────────────────────────────────────

# Returns 0 if the current directory looks like a checked-out
# Polaris repo (has deploy/docker-compose.yaml).
in_polaris_repo() {
    [[ -f "deploy/docker-compose.yaml" && -d "polaris-backend" ]]
}

clone_repo_if_needed() {
    if in_polaris_repo; then
        log "Detected existing Polaris checkout at ${PWD}"
        return 0
    fi
    local target="${POLARIS_INSTALL_DIR:-${PWD}/polaris}"
    if [[ -d "${target}/.git" ]]; then
        log "Re-using existing clone at ${target}"
    else
        log "Cloning ${REPO_URL} into ${target}"
        run git clone --depth 1 "${REPO_URL}" "${target}"
    fi
    run cd "${target}"
}

# ── Step 3: locate polaris-setup ─────────────────────────────────────────

# Detects the host arch in the naming convention the GitHub
# release assets use (linux-amd64 / linux-arm64). This branch is
# forward-compatible; today the publish workflow ships only Docker
# images, so the binary fetch falls through to a clear instruction.
detect_release_asset() {
    local uname_m
    uname_m="$(uname -m)"
    case "${uname_m}" in
        x86_64|amd64)
            printf 'polaris-setup-linux-amd64.tar.gz'
            ;;
        aarch64|arm64)
            printf 'polaris-setup-linux-arm64.tar.gz'
            ;;
        *)
            die "unsupported architecture: ${uname_m}"
            ;;
    esac
}

# Locate the polaris-setup binary: prefer one already on PATH;
# otherwise look in the in-repo `target/release/` and
# `target/debug/` build outputs; otherwise instruct the operator
# to build from source. We do NOT fetch a binary from a remote
# release today because the publish workflow lands later in this
# dispatch — the function is wired so a future workflow can drop
# binaries into the release assets and this script picks them up
# with a one-line edit.
locate_setup_binary() {
    if command -v "${SETUP_BIN_NAME}" >/dev/null 2>&1; then
        command -v "${SETUP_BIN_NAME}"
        return 0
    fi
    if [[ -x "target/release/${SETUP_BIN_NAME}" ]]; then
        printf '%s/target/release/%s' "${PWD}" "${SETUP_BIN_NAME}"
        return 0
    fi
    if [[ -x "target/debug/${SETUP_BIN_NAME}" ]]; then
        printf '%s/target/debug/%s' "${PWD}" "${SETUP_BIN_NAME}"
        return 0
    fi
    return 1
}

# Build polaris-setup from source via cargo. Used as a fallback
# when no published binary is on PATH and the operator has Rust
# available. We do NOT install rustup here — installing a
# toolchain on the operator's host without consent is out of
# scope for an "easy install" script.
build_setup_from_source() {
    if ! command -v cargo >/dev/null 2>&1; then
        cat >&2 <<'INSTRUCTIONS'
error: polaris-setup is not on PATH and cargo is unavailable to build it.

Options:
  1. Install Rust (https://rustup.rs/) and re-run this script.
  2. Pull the labeler-profile image directly and copy the binary out:
       docker create --name polaris-setup-tmp ghcr.io/dollspace-gay/polaris-backend:latest
       docker cp polaris-setup-tmp:/usr/local/bin/polaris-setup .
       docker rm polaris-setup-tmp
     Then re-run this script with ./polaris-setup on your PATH.
INSTRUCTIONS
        exit "${EXIT_PREREQ_MISSING}"
    fi
    log "Building polaris-setup from source (cargo build --release --bin polaris-setup)"
    run cargo build --release --bin polaris-setup
}

# ── Step 4: run polaris-setup ────────────────────────────────────────────

invoke_setup() {
    local setup_bin
    if ! setup_bin="$(locate_setup_binary)"; then
        build_setup_from_source
        setup_bin="$(locate_setup_binary)" || die "polaris-setup not found after build"
    fi
    log "Using polaris-setup binary at ${setup_bin}"

    # Decide interactive / non-interactive. Auto-detect (stdin a
    # tty) is the default; the env var is an override.
    local nonint_arg=""
    if [[ "${POLARIS_NONINTERACTIVE:-0}" == "1" ]] || [[ ! -t 0 ]]; then
        nonint_arg="--non-interactive"
        if [[ -z "${POLARIS_HOSTNAME:-}" ]]; then
            cat >&2 <<'MSG'
error: running in non-interactive mode but POLARIS_HOSTNAME is not set.

When this script is piped through curl|bash, there is no tty for prompts.
Set POLARIS_HOSTNAME in the environment before piping, e.g.:

   POLARIS_HOSTNAME=mod.example.com bash -c \
     'curl -sSL https://raw.githubusercontent.com/dollspace-gay/polaris/main/scripts/install.sh | bash'
MSG
            exit "${EXIT_PREREQ_MISSING}"
        fi
    fi

    local force_arg=""
    if [[ "${POLARIS_FORCE:-0}" == "1" ]]; then
        force_arg="--force"
    fi

    local host_arg=""
    if [[ -n "${POLARIS_HOSTNAME:-}" ]]; then
        host_arg="--hostname=${POLARIS_HOSTNAME}"
    fi

    log "Running polaris-setup"
    # `run` echoes (in --dry-run) or executes; the empty-string
    # args are filtered out so polaris-setup never sees a literal
    # "" positional.
    local -a argv=()
    [[ -n "${nonint_arg}" ]] && argv+=("${nonint_arg}")
    [[ -n "${force_arg}" ]] && argv+=("${force_arg}")
    [[ -n "${host_arg}" ]] && argv+=("${host_arg}")
    argv+=("--dir=deploy")

    if [[ "${DRY_RUN}" -eq 1 ]]; then
        printf '+ %s %s\n' "${setup_bin}" "${argv[*]}" >&2
        return 0
    fi
    if ! "${setup_bin}" "${argv[@]}"; then
        exit "${EXIT_SETUP_FAILED}"
    fi
}

# ── Step 5: print final command (DO NOT auto-run) ────────────────────────

print_next_steps() {
    cat <<'NEXT'

Polaris setup complete. To bring up the stack, run:

   docker compose -f deploy/docker-compose.yaml up -d

Then visit https://<your-hostname>/ in your browser to walk the
in-app setup wizard (sign the labeler service record, generate
the K-256 key, and submit the PLC update).

Review deploy/.env before bringing the stack up; it contains the
generated cookie key and Postgres password. The file is
chmod 0600; keep it that way and never commit it.

NEXT
}

# ── Main ────────────────────────────────────────────────────────────────

main() {
    check_prereqs
    clone_repo_if_needed
    invoke_setup
    print_next_steps
    # Clear the trap on a clean exit so it doesn't fire with the
    # success exit code.
    trap - EXIT
}

main "$@"
