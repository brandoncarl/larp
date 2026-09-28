#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "Usage: sh scripts/render-homebrew-formula.sh <version> <archive-sha256>" >&2
    exit 2
fi

version=$1
sha256=$2
case $version in
    ''|*[!0-9A-Za-z.-]*) echo "Invalid release version" >&2; exit 2 ;;
esac
case $sha256 in
    *[!0-9a-f]*) echo "Invalid SHA-256 digest" >&2; exit 2 ;;
esac
if [ "${#sha256}" -ne 64 ]; then
    echo "SHA-256 digest must be 64 lowercase hex characters" >&2
    exit 2
fi

source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
package_version=$(sed -n 's/^version = "\([^"]*\)"$/\1/p' "$source_dir/Cargo.toml" | head -n 1)
if [ "$version" != "$package_version" ]; then
    echo "Release version does not match Cargo.toml" >&2
    exit 2
fi
sed -e "s/@VERSION@/$version/g" -e "s/@SHA256@/$sha256/g" \
    "$source_dir/packaging/homebrew/larp.rb.in"
