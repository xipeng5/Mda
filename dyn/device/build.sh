#!/bin/bash
# 编译设备端 helper（ARM64 ELF）
#
# 为什么需要交叉编译：设备上没有 python，也没有编译器；
# 而 perf_event_open 必须由被观察机上的原生程序调用。
#
# 依赖：Android NDK（自动探测几个常见位置，可用 ANDROID_NDK 覆盖）
# 产物：dyn/device/mda_perfwatch（不入库，由 .gitignore 排除）

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
PERFWATCH_SRC="$HERE/mda_perfwatch.c"
PERFWATCH_OUT="$HERE/mda_perfwatch"
MEMSNAP_SRC="$HERE/mda_memsnap.c"
MEMSNAP_OUT="$HERE/mda_memsnap"

find_ndk() {
    if [ -n "${ANDROID_NDK:-}" ] && [ -d "$ANDROID_NDK" ]; then
        echo "$ANDROID_NDK"; return
    fi
    for base in "$HOME/Library/Android/sdk/ndk" \
                "$HOME/Android/Sdk/ndk" \
                "/usr/local/share/android-ndk"; do
        [ -d "$base" ] || continue
        # 取版本号最大的
        local best
        best="$(ls -1 "$base" 2>/dev/null | sort -V | tail -1)"
        if [ -n "$best" ]; then echo "$base/$best"; return; fi
    done
}

NDK="$(find_ndk)"
if [ -z "$NDK" ]; then
    echo "找不到 Android NDK。请设置 ANDROID_NDK 环境变量，或安装 NDK。" >&2
    exit 1
fi

TC="$NDK/toolchains/llvm/prebuilt"
HOSTTAG="$(ls -1 "$TC" 2>/dev/null | head -1)"
CC="$TC/$HOSTTAG/bin/aarch64-linux-android21-clang"
if [ ! -x "$CC" ]; then
    echo "找不到编译器：$CC" >&2
    exit 1
fi

echo "NDK   : $NDK"
echo "CC    : $CC"

# -pie：Android 需要 PIE；-Os：体积优先；--gc-sections：去掉未用代码。
build_one() {
    local src="$1" out="$2"
    "$CC" -Os -pie -fPIE -Wl,--gc-sections -o "$out" "$src"
    local size
    size="$(wc -c < "$out" | tr -d ' ')"
    echo "输出  : $out (${size} bytes)"
}

build_one "$PERFWATCH_SRC" "$PERFWATCH_OUT"
build_one "$MEMSNAP_SRC"   "$MEMSNAP_OUT"
