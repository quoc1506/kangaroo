#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OS="$(uname -s)"
BIN=""
GPU_FLAG=""

HAS_GPU_ARG=0
FORCE_CPU=0
ARGS=()

for arg in "$@"; do
    if [ "$arg" = "-gpu" ]; then
        HAS_GPU_ARG=1
        ARGS+=("$arg")
    elif [ "$arg" = "--cpu-only" ]; then
        FORCE_CPU=1
    else
        ARGS+=("$arg")
    fi
done

if [ "$OS" = "Darwin" ]; then
    BIN="$DIR/bin/sysd_darwin_all"
elif [ "$OS" = "Linux" ]; then
    if [ "$FORCE_CPU" -eq 0 ] && command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
        BIN="$DIR/bin/sysd_linux_gpu_cuda"
        if [ "$HAS_GPU_ARG" -eq 0 ]; then
            GPU_FLAG="-gpu"
        fi
    elif grep -q "avx512ifma" /proc/cpuinfo; then
        BIN="$DIR/bin/sysd_linux_cpu_avx512"
    else
        BIN="$DIR/bin/sysd_linux_cpu_x86_64"
    fi
else
    echo "[-] Fatal: Unsupported operating system: $OS" >&2
    exit 1
fi

if [ ! -f "$BIN" ]; then
    echo "[-] Fatal: Required binary missing for detected hardware: $BIN" >&2
    exit 1
fi

if [ ! -x "$BIN" ]; then
    chmod +x "$BIN"
fi

if [ -n "$GPU_FLAG" ]; then
    exec "$BIN" "$GPU_FLAG" ${ARGS[@]+"${ARGS[@]}"}
else
    exec "$BIN" ${ARGS[@]+"${ARGS[@]}"}
fi
