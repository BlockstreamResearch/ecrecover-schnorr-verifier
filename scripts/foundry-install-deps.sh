#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

if [ -d "$ROOT/lib/forge-std/src" ]; then
    exit 0
fi

mkdir -p "$ROOT/lib"

forge install \
    --root "$ROOT" \
    --no-git \
    --shallow \
    forge-std=foundry-rs/forge-std@v1.9.7
