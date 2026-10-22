#!/usr/bin/env bash
set -e

BIN=""
OS="$(uname -s)"

if [ "$OS" = "Darwin" ]; then
    DARWIN_CANDIDATES=(
        "./bin/sysd_darwin_all"
        "./sysd_darwin_all"
        "./bin/sysd_darwin"
        "./sysd_darwin"
        "./bin/sysd_darwin_arm64"
        "./sysd_darwin_arm64"
        "./bin/sysd_darwin_x86_64"
        "./sysd_darwin_x86_64"
        "./bin/sysd"
        "./sysd"
    )
    for c in "${DARWIN_CANDIDATES[@]}"; do
        if [ -f "$c" ]; then
            BIN="$c"
            break
        fi
    done
else
    if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
        for c in "./bin/sysd_linux_gpu_cuda" "./sysd_linux_gpu_cuda"; do
            if [ -f "$c" ]; then
                BIN="$c"
                break
            fi
        done
    fi

    if [ -z "$BIN" ]; then
        LINUX_CANDIDATES=(
            "./bin/sysd_linux_cpu_x86_64"
            "./sysd_linux_cpu_x86_64"
            "./bin/sysd"
            "./sysd"
        )
        for c in "${LINUX_CANDIDATES[@]}"; do
            if [ -f "$c" ]; then
                BIN="$c"
                break
            fi
        done
    fi
fi

if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERR] Binary not found in ./bin/ or current directory." >> error.log 2>&1
    exit 1
fi

chmod +x "$BIN" 2>/dev/null || true
exec "$BIN" "$@" > /dev/null 2>> error.log