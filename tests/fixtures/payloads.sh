#!/usr/bin/env bash
# Builds the partition images and payloads the tests read, into /work/out.
# Runs in an x86-64 Linux container with otatools at /ota, next to the
# libraries and DEX files build.sh compiled into /work.
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

erofs() {
    mkfs.erofs -T0 --all-root -U 00000000-0000-0000-0000-000000000000 --quiet "$@"
}

# Full payloads: compressible, incompressible and mixed partitions. The
# incompressible one makes the payload span many HTTP range requests.
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

# Files in filesystem images: executables for zucchini, an APK for puffin, a
# file only the newer image has, and text, uncompressed and compressed with
# LZ4 and LZ4HC.
noise $((192 * KiB)) | base64 >"$img/apk-text"
for version in older newer; do
    tree=$img/files-$version
    mkdir -p "$tree/lib" "$tree/app"
    cp /work/elf/$version/*.so "$tree/lib/"
    {
        printf 'vdex027\0'
        zeros 24
        cat /work/dex/$version/classes.dex
    } >"$tree/app/app.vdex"
    # A small change early in poorly compressible text rewrites all the
    # deflate output after it, which puffin diffs far better than bsdiff.
    {
        head -c $((8 * KiB)) "$img/apk-text"
        [[ $version == newer ]] && text $((2 * KiB)) changed
        tail -c +$((8 * KiB + 1)) "$img/apk-text"
    } >"$tree/app/notes.txt"
    cp /work/dex/$version/classes.dex "$tree/app/classes.dex"
    soong_zip -o "$tree/app/app.apk" -C "$tree/app" -f "$tree/app/notes.txt" -f "$tree/app/classes.dex"
    rm "$tree/app/classes.dex"
    # Diffing against the most similar old file loses to compressing this.
    [[ $version == newer ]] && (yes 'only in the newer image' || true) | head -c $((64 * KiB)) >"$tree/added.txt"
    # The generator reads no file types from EROFS images, and only looks for
    # deflate streams in regular files, so this image is ext4.
    mke2fs -q -t ext4 -b 4096 -O ^has_journal -d "$tree" "$img/files-$version.img" 1M

    # Compressed files: text, a zip whose deflate streams lz4diff patches
    # with puffin, and data that is partly incompressible, which EROFS stores
    # in uncompressed clusters.
    packed=$img/packed-$version
    mkdir -p "$packed/docs"
    text $((384 * KiB)) "$version a" >"$packed/a.txt"
    text $((160 * KiB)) "$version b" >"$packed/b.txt"
    {
        text $((24 * KiB)) notes
        [[ $version == newer ]] && text $((2 * KiB)) changed
        text $((96 * KiB)) "more notes"
    } >"$packed/docs/notes.txt"
    soong_zip -o "$packed/docs.zip" -C "$packed/docs" -f "$packed/docs/notes.txt"
    rm -r "$packed/docs"
    {
        text $((64 * KiB)) "$version mixed"
        head -c $((96 * KiB)) "$img/apk-text" | base64 -d
    } >"$packed/mixed.bin"
    erofs -zlz4hc,9 "$img/lz4hc-$version.img" "$packed"
    erofs -zlz4 "$img/lz4-$version.img" "$packed"
done
keep files files "$img/files-older.img"
payload files --minor_version=10 --enable_replace_zstd --partition_names=files \
    --old_partitions="$img/files-older.img" --new_partitions="$img/files-newer.img"
for compression in lz4hc,9 lz4; do
    name=${compression%%,*}
    keep "$name" "$name" "$img/$name-older.img"
    payload "$name" --minor_version=9 --enable_lz4diff=true --erofs_compression_param="$compression" \
        --partition_names="$name" --old_partitions="$img/$name-older.img" --new_partitions="$img/$name-newer.img"
done

# Verity: hash trees and FEC that the device computes after installing a
# delta, for each hash algorithm and several FEC root counts.
noise $((64 * KiB)) >"$img/verity-noise"
# verity IMAGE ALGORITHM ROOTS TAG
verity() {
    {
        text $((512 * KiB)) "$4"
        cat "$img/verity-noise"
        text $((256 * KiB)) tail
    } >"$1"
    avbtool add_hashtree_footer --image "$1" --partition_name verity --partition_size $((1024 * KiB)) \
        --hash_algorithm "$2" --fec_num_roots "$3" --salt 5eed5eed
}
older=()
newer=()
for build in sha1:2 sha256:4 sha512:8; do
    algorithm=${build%%:*}
    roots=${build#*:}
    for version in older newer; do
        verity "$img/$algorithm-$version.img" "$algorithm" "$roots" "$version"
    done
    keep verity "$algorithm" "$img/$algorithm-older.img"
    older+=("$img/$algorithm-older.img")
    newer+=("$img/$algorithm-newer.img")
done
payload verity --minor_version=9 --partition_names=sha1:sha256:sha512 \
    --old_partitions="$(IFS=:; echo "${older[*]}")" --new_partitions="$(IFS=:; echo "${newer[*]}")"

# Zucchini patches between the two builds of each executable, and between
# unrelated data.
mkdir -p "$out/zucchini"
for older in /work/elf/older/*.so /work/dex/older/classes.dex; do
    file=${older#/work/*/older/}
    name=${file%.*}
    newer=${older/\/older\//\/newer\/}
    cp "$older" "$out/zucchini/$name.older"
    cp "$newer" "$out/zucchini/$name.newer"
    zucchini -gen "$older" "$newer" "$out/zucchini/$name.zuc" >/dev/null
done
noise $((64 * KiB)) >"$out/zucchini/raw.older"
{
    head -c $((32 * KiB)) "$out/zucchini/raw.older"
    noise $((8 * KiB))
    tail -c $((32 * KiB)) "$out/zucchini/raw.older"
} >"$out/zucchini/raw.newer"
zucchini -gen -raw "$out/zucchini/raw.older" "$out/zucchini/raw.newer" "$out/zucchini/raw.zuc" >/dev/null
