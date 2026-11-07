#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ "${1:-}" == --native ]]; then
    shift
    exec python3 reproduction/run.py "$@"
fi
if [[ "${1:-}" == --help || "${1:-}" == -h ]]; then
    exec python3 reproduction/run.py --help
fi

docker build -f reproduction/Dockerfile -t cedar-oopsla2024-reproduction:local .
git_common_directory="$(git rev-parse --path-format=absolute --git-common-dir)"
exec docker run --rm --cpus=4 --memory=8g \
    --user "$(id -u):$(id -g)" -e HOME=/tmp -e GOMAXPROCS=4 \
    -v "$PWD:/workspace" -w /workspace \
    -v "$git_common_directory:$git_common_directory:ro" \
    -e GIT_WORK_TREE=/workspace -e GIT_OPTIONAL_LOCKS=0 \
    cedar-oopsla2024-reproduction:local \
    python3 reproduction/run.py --container "$@"
