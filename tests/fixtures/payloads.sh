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

# keep CASE PARTITION IMAGE: keeps the image a delta case updates.
keep() {
    mkdir -p "$out/$1/old"
    cp "$3" "$out/$1/old/$2.img"
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

# Deltas of raw images: moved, rewritten, zeroed and new blocks. All three
# update the image kept for the first.
noise $((128 * KiB)) >"$img/shared"
{
    cat "$img/shared"
    text $((512 * KiB)) older
    noise $((32 * KiB))
    zeros $((128 * KiB))
} >"$img/raw-older.img"
{
    text $((128 * KiB)) moved
    cat "$img/shared"
    text $((512 * KiB)) newer
    zeros $((128 * KiB))
    noise $((32 * KiB))
} >"$img/raw-newer.img"
keep delta raw "$img/raw-older.img"
# Minor version 3 predates BROTLI_BSDIFF and ZERO, so it yields SOURCE_BSDIFF
# patches; BSDF2 patches can compress their streams with bzip2 instead of
# brotli.
for name in delta delta-bz2 delta-v3; do
    case $name in
        delta) flags=(--minor_version=9) ;;
        delta-bz2) flags=(--minor_version=9 --compressor_types=bz2) ;;
        delta-v3) flags=(--minor_version=3) ;;
    esac
    payload "$name" "${flags[@]}" --partition_names=raw \
        --old_partitions="$img/raw-older.img" --new_partitions="$img/raw-newer.img"
done
