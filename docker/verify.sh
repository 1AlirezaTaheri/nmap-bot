#!/bin/sh
# Run the test suite against the working tree.
#
# Installs runtime + dev requirements into a throwaway python:3.11-slim
# container, so nothing is added to the host and the production images stay
# free of test tooling.
#
#   ./docker/verify.sh                 # everything
#   ./docker/verify.sh tests/test_security.py
#
# Pass --user "$(id -u):$(id -g)" to write caches as yourself rather than root.
set -eu

cd "$(dirname "$0")/.."

exec docker run --rm \
    -v "$PWD:/src" \
    -w /src \
    --entrypoint sh \
    python:3.11-slim -c '
        set -eu
        pip install --quiet --disable-pip-version-check \
            -r requirements.txt -r requirements-dev.txt
        python -m pytest "$@"
    ' sh "$@"
