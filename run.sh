#!/usr/bin/env bash
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN=""
OS="$(uname -s)"

if [ "$OS" = "Darwin" ]; then
    for c in "$DIR/bin/sysd_darwin_all" "$DIR/sysd_darwin_all" "$DIR/bin/sysd" "$DIR/sysd"; do
        if [ -f "$c" ]; then
            BIN="$c"
            break
        fi
    done
elif [ "$OS" = "Linux" ]; then
    if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
        for c in "$DIR/bin/sysd_linux_gpu_cuda" "$DIR/sysd_linux_gpu_cuda"; do
            if [ -f "$c" ]; then
                BIN="$c"
                break
            fi
        done
    fi
    if [ -z "$BIN" ]; then
        for c in "$DIR/bin/sysd_linux_cpu_x86_64" "$DIR/sysd_linux_cpu_x86_64" "$DIR/bin/sysd" "$DIR/sysd"; do
            if [ -f "$c" ]; then
                BIN="$c"
                break
            fi
        done
    fi
fi

if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
    exit 1
fi

chmod +x "$BIN" 2>/dev/null || true

for arg in "$@"; do
    if [ "$arg" = "--verify" ]; then
        exec "$BIN" "$@"
    fi
done

exec "$BIN" "$@" >/dev/null 2>&1
