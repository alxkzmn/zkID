#!/usr/bin/env bash
set -euo pipefail

baseline_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
baseline_env=${OPENAC_FORMAL_ENV:-/workspace/formal-tools/env.sh}
if [[ ! -r "$baseline_env" ]]; then
    printf 'Prepared environment missing: %s\n' "$baseline_env" >&2
    exit 2
fi
source "$baseline_env"
export OPENAC_FORMAL_ENV="$baseline_env"
export BASELINE_NATIVE_TARGET_DIR=${BASELINE_NATIVE_TARGET_DIR:-$CARGO_TARGET_DIR}
export BASELINE_MIRI_TARGET_DIR=${BASELINE_MIRI_TARGET_DIR:-${CARGO_TARGET_DIR}-charon-miri}
exec python3 "$baseline_dir/collect.py" "$@"
