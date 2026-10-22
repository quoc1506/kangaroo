#!/usr/bin/env bash
set -e

BIN=""
CANDIDATES=(
    "./bin/sysd_linux_gpu_cuda"
    "./sysd_linux_gpu_cuda"
    "./bin/sysd_linux_cpu_x86_64"
    "./sysd_linux_cpu_x86_64"
    "./bin/sysd"
    "./sysd"
)

if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
    for c in "./bin/sysd_linux_gpu_cuda" "./sysd_linux_gpu_cuda"; do
        if [ -f "$c" ]; then
            BIN="$c"
            break
        fi
    done
fi

if [ -z "$BIN" ]; then
    for c in "${CANDIDATES[@]}"; do
        if [ -f "$c" ]; then
            BIN="$c"
            break
        fi
    done
fi

if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [ERR] Binary not found in ./bin/ or current directory." >> error.log 2>&1
    exit 1
fi

chmod +x "$BIN" 2>/dev/null || true
exec "$BIN" "$@" > /dev/null 2>> error.log