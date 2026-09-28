#!/bin/sh
set -eu

if [ -n "${RUSTFLAGS:-}" ]; then
    echo "Use CARGO_ENCODED_RUSTFLAGS with this build script; RUSTFLAGS would be ignored." >&2
    exit 2
fi

builder_home=${HOME:?HOME must be set}
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
separator=$(printf '\037')
privacy_flags="--remap-path-prefix=${builder_home}=/build${separator}--remap-path-prefix=${source_dir}=/src"
if [ -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]; then
    export CARGO_ENCODED_RUSTFLAGS="${CARGO_ENCODED_RUSTFLAGS}${separator}${privacy_flags}"
else
    export CARGO_ENCODED_RUSTFLAGS=${privacy_flags}
fi

cd "$source_dir"
cargo build --release "$@"

if LC_ALL=C grep -a -Eq '/Users/[^/[:space:]]+|/home/[^/[:space:]]+' target/release/larp; then
    echo "Release binary contains a builder home path; refusing this build." >&2
    exit 1
fi
if LC_ALL=C grep -a -Fq "$source_dir" target/release/larp; then
    echo "Release binary contains the source checkout path; refusing this build." >&2
    exit 1
fi
