#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    echo "Usage: sh scripts/render-homebrew-formula.sh <version> <arm64-sha256> <intel-sha256>" >&2
    exit 2
fi

version=$1
arm_sha256=$2
intel_sha256=$3
case $version in
    ''|*[!0-9A-Za-z.-]*) echo "Invalid release version" >&2; exit 2 ;;
esac
for digest in "$arm_sha256" "$intel_sha256"; do
    case $digest in
        *[!0-9a-f]*) echo "Invalid SHA-256 digest" >&2; exit 2 ;;
    esac
    if [ "${#digest}" -ne 64 ]; then
        echo "SHA-256 digest must be 64 lowercase hex characters" >&2
        exit 2
    fi
done

source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
package_version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$source_dir/Cargo.toml" | head -n 1)
if [ "$version" != "$package_version" ]; then
    echo "Release version does not match Cargo.toml" >&2
    exit 2
fi
sed -e "s/@VERSION@/$version/g" \
    -e "s/@ARM_SHA256@/$arm_sha256/g" \
    -e "s/@INTEL_SHA256@/$intel_sha256/g" \
    "$source_dir/packaging/homebrew/larp.rb.in"
