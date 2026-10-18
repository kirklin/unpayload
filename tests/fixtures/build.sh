#!/usr/bin/env bash
# Regenerates tests/data from the sources here. Needs Docker and otatools.zip
# from an Android build, unpacked (OTATOOLS). Intermediate files and generator
# logs stay in WORK when it is set.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
: "${OTATOOLS:?set OTATOOLS to an unpacked otatools.zip}"

if [[ -n ${WORK:-} ]]; then
    work=$WORK
    rm -rf "$work"
    mkdir -p "$work"
else
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
fi

docker run --rm --platform linux/amd64 \
    -v "$OTATOOLS:/ota:ro" -v "$here:/fixtures:ro" -v "$work:/work" \
    ubuntu:24.04 /fixtures/payloads.sh

rm -rf "$root/tests/data"
cp -R "$work/out" "$root/tests/data"
