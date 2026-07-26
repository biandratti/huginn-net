#!/usr/bin/env bash
#
# Usage: ./scripts/bump-version.sh <new-version>
#
# Replaces the current workspace version (read from Cargo.toml) with
# <new-version> across Cargo.toml and all crate README.md files.
set -euo pipefail

NEW=${1:-}
if [ -z "$NEW" ]; then
  echo "Usage: $0 <new-version>"
  exit 1
fi

OLD=$(grep '^version = ' Cargo.toml | grep -oP '[\d]+\.[\d]+\.[\d]+[^"]*')
OLD_ESC=$(echo "$OLD" | sed 's/[.]/\\./g; s/-/\\-/g')

FILES=(
  Cargo.toml
  README.md
  huginn-net/README.md
  huginn-net-db/README.md
  huginn-net-tcp/README.md
  huginn-net-http/README.md
  huginn-net-tls/README.md
)

echo "Bumping $OLD → $NEW"
for f in "${FILES[@]}"; do
  sed -i "s/$OLD_ESC/$NEW/g" "$f"
  echo "  $f"
done