#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
image_name="${KEYMAN_TEST_IMAGE:-keyman-softhsm:latest}"
if [[ -n "${CONTAINER_RUNTIME:-}" ]]; then
    container_runtime="$CONTAINER_RUNTIME"
elif command -v docker >/dev/null 2>&1; then
    container_runtime="docker"
else
    container_runtime="podman"
fi
if [[ -n "${CONTAINER_BUILD_FLAGS+x}" ]]; then
    read -r -a container_build_flags <<< "$CONTAINER_BUILD_FLAGS"
elif [[ "$container_runtime" == "podman" ]]; then
    container_build_flags=(--pull=missing)
else
    container_build_flags=()
fi

"$container_runtime" build "${container_build_flags[@]}" -t "$image_name" -f "$repo_dir/build/Dockerfile.softhsm" "$repo_dir"
"$container_runtime" run --rm "$image_name"
