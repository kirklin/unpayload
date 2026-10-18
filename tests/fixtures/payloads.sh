#!/usr/bin/env bash
# Builds the partition images and payloads the tests read, into /work/out.
# Runs in an x86-64 Linux container with otatools at /ota.
set -euo pipefail
export PATH=/ota/bin:$PATH
export LD_LIBRARY_PATH=/ota/lib64

out=/work/out
img=/work/img
mkdir -p "$out" "$img"
KiB=1024

# seq stops on a broken pipe once head has enough.
text() { (seq -f "line %08g $2" 1 1000000 || true) | head -c "$1"; }
noise() { head -c "$1" /dev/urandom; }
zeros() { head -c "$1" /dev/zero; }

# payload CASE [delta_generator flags...]
payload() {
    local name=$1
    shift
    mkdir -p "$out/$name"
    if ! delta_generator --out_file="$out/$name/payload.bin" "$@" >"$img/$name.log" 2>&1; then
        cat "$img/$name.log"
        exit 1
    fi
}

# Full payloads: compressible, incompressible and mixed partitions.
text $((1024 * KiB)) full >"$img/text.img"
noise $((1024 * KiB)) >"$img/noise.img"
{
    text $((256 * KiB)) mixed
    zeros $((256 * KiB))
    noise $((64 * KiB))
    text $((128 * KiB)) tail
} >"$img/mixed.img"
payload full --partition_names=text:noise:mixed \
    --new_partitions="$img/text.img:$img/noise.img:$img/mixed.img"
payload full-zstd --enable_replace_zstd --partition_names=text:mixed \
    --new_partitions="$img/text.img:$img/mixed.img"
