#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN=""
OS="$(uname -s)"
GPU_FLAG=""

HAS_GPU_ARG=0
for arg in "$@"; do
    if [ "$arg" = "-gpu" ]; then
        HAS_GPU_ARG=1
        break
    fi
done

if [ "$OS" = "Darwin" ]; then
    if [ -f "$DIR/bin/sysd_darwin_all" ]; then
        BIN="$DIR/bin/sysd_darwin_all"
    fi
elif [ "$OS" = "Linux" ]; then
    if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
        if [ -f "$DIR/bin/sysd_linux_gpu_cuda" ]; then
            BIN="$DIR/bin/sysd_linux_gpu_cuda"
            if [ "$HAS_GPU_ARG" -eq 0 ]; then
                GPU_FLAG="-gpu"
            fi
        fi
    fi
    if [ -z "$BIN" ]; then
        if [ -f "$DIR/bin/sysd_linux_cpu_avx512" ] && grep -q "avx512ifma" /proc/cpuinfo 2>/dev/null; then
            BIN="$DIR/bin/sysd_linux_cpu_avx512"
        elif [ -f "$DIR/bin/sysd_linux_cpu_x86_64" ]; then
            BIN="$DIR/bin/sysd_linux_cpu_x86_64"
        fi
    fi
fi

if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
    echo "[-] Error: Binary not found: ${BIN:-in bin/}" >&2
    exit 1
fi

chmod +x "$BIN" 2>/dev/null || true

if [ -n "$GPU_FLAG" ]; then
    exec "$BIN" "$GPU_FLAG" "$@"
else
    exec "$BIN" "$@"
fi
