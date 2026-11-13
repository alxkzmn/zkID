#!/usr/bin/env bash
set -euo pipefail
experiment_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
export OPENAC_FORMAL_ENV=${OPENAC_FORMAL_ENV:-/workspace/formal-tools/env.sh}
source "$OPENAC_FORMAL_ENV"
export EXPERIMENT_NATIVE_TARGET_DIR=${EXPERIMENT_NATIVE_TARGET_DIR:-$CARGO_TARGET_DIR}
export EXPERIMENT_MIRI_TARGET_DIR=${EXPERIMENT_MIRI_TARGET_DIR:-${CARGO_TARGET_DIR}-charon-miri}
exec python3 "$experiment_dir/retry.py" "$@"
