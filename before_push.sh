#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# Global function return value
RET_VALUE=0

VERBOSE=0
START_TIME=$(date +%s)

# @argument message
function print_message() {
    CURRENT_TIME=$(date +%s)
    TIME_ELAPSED=$(( CURRENT_TIME - START_TIME ))
    echo "${1} ... (+${TIME_ELAPSED}s)"
}

# @argument Description
function print_step() {
    print_message "${1}"
}

# @argument Key
# @argument Value
function print_config() {
    print_message "[Config] ${1}=${2}"
}

# @argument Description
function print_error() {
    print_message "[ERROR] ${1}"
}

# @argument Execution status (0=success, >=1=fail)
# @argument Description
function print_result() {
    if [ x"${1}" = x0 ]; then
        print_message "[PASS] ${2}"
    else
        print_message "[FAIL] ${2}"
    fi
}

# @argument Command to test
function check_command_exist() {
    set +e
    command -v ${1} > /dev/null
    if [ x"$?" = "x1" ]; then
        print_error "command not found: ${1}"
        exit 1
    fi
    set -e
}

# @argument Command to run
# @argument Command to run under verbose option
function command_suite() {
    if [ x"${VERBOSE}" = x0 ]; then
        CMD="${1}"
    else
        CMD="${2}"
        print_step "${CMD}"
    fi

    set +e
    eval "${CMD}"
    RESULT=$?
    set -e

    print_result "${RESULT}" "${CMD}"
    if [ x"${RESULT}" != x0 ]; then
        exit "${RESULT}"
    fi
}

function help()
{
    cat << HELP >&2
Usage:
    ./before_push.sh [-v]
    -v | --verbose      Display command execution logs
    -h | --help         Show help
HELP
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        -v | --verbose)
        VERBOSE=1
        shift 1
        ;;
        -h | --help)
        help
        ;;
        *)
        print_message "Unknown argument: $1"
        help
        ;;
    esac
done

check_command_exist "cargo"
check_command_exist "rustup"

RUSTFLAGS="${RUSTFLAGS:-} -D warnings"
command_suite "cargo build --quiet" "cargo build"

command_suite "cargo test --quiet" "cargo test"

rustfmt --version > /dev/null || rustup component add rustfmt
command_suite "cargo fmt --quiet -- --check --color=auto" "cargo fmt -- --check --color=auto"

cargo-clippy --version > /dev/null || rustup component add clippy
command_suite "cargo clippy --quiet -- -D warnings" "cargo clippy -- -D warnings"

cargo-audit -h > /dev/null || cargo install cargo-audit
command_suite "cargo audit --quiet" "cargo audit"

