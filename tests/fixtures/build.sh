#!/usr/bin/env bash
# Regenerates tests/data from the sources here. Needs the Android NDK, build
# tools and a platform android.jar, a JDK, Docker, and otatools.zip from an
# Android build, unpacked (OTATOOLS). Intermediate files and generator logs
# stay in WORK when it is set.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
: "${ANDROID_HOME:=$HOME/Library/Android/sdk}"
: "${NDK:=$(ls -d "$ANDROID_HOME"/ndk/* | sort -V | tail -1)}"
: "${BUILD_TOOLS:=$(ls -d "$ANDROID_HOME"/build-tools/* | sort -V | tail -1)}"
: "${PLATFORM:=$(ls -d "$ANDROID_HOME"/platforms/android-* | sort -V | tail -1)}"
: "${OTATOOLS:?set OTATOOLS to an unpacked otatools.zip}"

if [[ -n ${WORK:-} ]]; then
    work=$WORK
    rm -rf "$work"
    mkdir -p "$work"
else
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
fi
toolchain=$(ls -d "$NDK"/toolchains/llvm/prebuilt/*/bin | head -1)

# The library for every architecture zucchini disassembles, with 32-bit ARM
# built both as THUMB2 and as ARM code. API level 21 keeps plain REL and
# RELA relocation sections; zucchini ignores RELA addends and reads the
# addresses relocations adjust from the image, so the linker stores them.
# The toolchain's identification in .comment is left out.
for build in x86:i686 x64:x86_64 arm64:aarch64 thumb:armv7a arm:armv7a; do
    name=${build%%:*}
    triple=${build#*:}-linux-android21
    [[ $name == thumb || $name == arm ]] && triple=armv7a-linux-androideabi21
    flags=(-O2 -fPIC -shared -Wl,--apply-dynamic-relocs)
    [[ $name == thumb ]] && flags+=(-mthumb)
    [[ $name == arm ]] && flags+=(-marm)
    for version in older newer; do
        mkdir -p "$work/elf/$version"
        defines=()
        [[ $version == newer ]] && defines=(-DNEWER)
        "$toolchain/clang" --target="$triple" "${flags[@]}" ${defines[@]+"${defines[@]}"} \
            -o "$work/elf/$version/lib$name.so" "$here/lib.c"
        "$toolchain/llvm-objcopy" --remove-section=.comment "$work/elf/$version/lib$name.so"
    done
done

for version in older newer; do
    mkdir -p "$work/dex/$version/classes"
    javac --release 11 -d "$work/dex/$version/classes" "$here"/dex/common/*.java "$here/dex/$version"/*.java
    find "$work/dex/$version/classes" -name '*.class' -print0 |
        xargs -0 "$BUILD_TOOLS/d8" --release --min-api 26 --lib "$PLATFORM/android.jar" --output "$work/dex/$version"
done

docker run --rm --platform linux/amd64 \
    -v "$OTATOOLS:/ota:ro" -v "$here:/fixtures:ro" -v "$work:/work" \
    ubuntu:24.04 /fixtures/payloads.sh

rm -rf "$root/tests/data"
cp -R "$work/out" "$root/tests/data"
