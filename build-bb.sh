#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# build-bb.sh - build busybox for aarch64, armhf, x86_64, x86
# statically linked, optimized (LTO), and stripped, using musl cross-compilers.
#
# Usage:
#   ./build-bb.sh         - run defconfig, menuconfig, then build all
#   ./build-bb.sh clean   - run make clean

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
OUT_DIR="$SCRIPT_DIR/out"
TOOLCHAIN_BASE="$HOME/toolchains"
JOBS="$(nproc)"

declare -A ARCH_CROSS=(
    [aarch64]="aarch64-linux-musl"
    [armhf]="arm-linux-musleabihf"
    [x86_64]="x86_64-linux-musl"
    [x86]="i686-linux-musl"
)

declare -A ARCH_MAKE=(
    [aarch64]="arm64"
    [armhf]="arm"
    [x86_64]="x86_64"
    [x86]="x86"
)

declare -A ARCH_TOOLCHAIN=(
    [aarch64]="aarch64-linux-musl-cross"
    [armhf]="arm-linux-musleabihf-cross"
    [x86_64]="x86_64-linux-musl-cross"
    [x86]="i686-linux-musl-cross"
)

check_compilers()
{
    local missing=0

    for arch in "${!ARCH_CROSS[@]}"; do
        local tc_dir="$TOOLCHAIN_BASE/${ARCH_TOOLCHAIN[$arch]}"
        local gcc="$tc_dir/bin/${ARCH_CROSS[$arch]}-gcc"

        if [ ! -x "$gcc" ]; then
            echo "missing compiler for $arch: $gcc"
            missing=1
        fi
    done

    if [ "$missing" -eq 1 ]; then
        echo "one or more compilers not found under $TOOLCHAIN_BASE"
        exit 1
    fi
}

do_clean()
{
    cd "$SCRIPT_DIR" || exit 1
    echo "running make clean"
    make clean
    echo "removing output directory"
    rm -rf "$OUT_DIR"
}

do_defconfig()
{
    cd "$SCRIPT_DIR" || exit 1
    echo "using droidspaces.config as the base config"
    cp "$SCRIPT_DIR/droidspaces.config" "$SCRIPT_DIR/.config"
}

do_menuconfig()
{
    cd "$SCRIPT_DIR" || exit 1
    echo "launching menuconfig"
    make menuconfig
}

build_arch()
{
    local arch="$1"
    local cross="${ARCH_CROSS[$arch]}"
    local make_arch="${ARCH_MAKE[$arch]}"
    local tc_bin="$TOOLCHAIN_BASE/${ARCH_TOOLCHAIN[$arch]}/bin"
    local output="$OUT_DIR/busybox-${arch}"

    echo "building for $arch (CROSS_COMPILE=$cross- with LTO)"

    local opt_cflags="-flto -Os -ffunction-sections -fdata-sections"
    local opt_ldflags="-flto -Wl,--gc-sections"

    # Pass AR and NM pointing to the gcc wrapper versions to handle LTO objects properly
    make -C "$SCRIPT_DIR" \
        ARCH="$make_arch" \
        CROSS_COMPILE="$tc_bin/$cross-" \
        AR="$tc_bin/$cross-gcc-ar" \
        NM="$tc_bin/$cross-gcc-nm" \
        CONFIG_STATIC=y \
        CONFIG_STRIP_STRIPPED=y \
        EXTRA_CFLAGS="$opt_cflags" \
        EXTRA_LDFLAGS="$opt_ldflags" \
        -j"$JOBS"

    if [ "${PIPESTATUS[0]}" -ne 0 ]; then
        echo "build failed for $arch"
        exit 1
    fi

    cp "$SCRIPT_DIR/busybox" "$output"
    "$tc_bin/$cross-strip" "$output"
    echo "output: $output"
}

if [ "$1" = "clean" ]; then
    do_clean
    exit 0
fi

check_compilers

# Ensure output directory exists
mkdir -p "$OUT_DIR"

do_defconfig
do_menuconfig

for arch in aarch64 armhf x86_64 x86; do
    build_arch "$arch"
done

echo "all builds done"
