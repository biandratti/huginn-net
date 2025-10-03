#!/bin/bash

# How to use: ./scripts/update-version.sh 1.6.0

set -e

if [ $# -eq 0 ]; then
    echo "Error: Provide new version"
    echo "Usage: $0 <new_version>"
    echo "Example: $0 1.6.0"
    exit 1
fi

NEW_VERSION=$1

echo "Updating workspace dependencies to version $NEW_VERSION..."
sed -i "s/huginn-net-db = { path = \"huginn-net-db\", version = \".*\" }/huginn-net-db = { path = \"huginn-net-db\", version = \"$NEW_VERSION\" }/" Cargo.toml
sed -i "s/huginn-net-tcp = { path = \"huginn-net-tcp\", version = \".*\" }/huginn-net-tcp = { path = \"huginn-net-tcp\", version = \"$NEW_VERSION\" }/" Cargo.toml
sed -i "s/huginn-net-http = { path = \"huginn-net-http\", version = \".*\" }/huginn-net-http = { path = \"huginn-net-http\", version = \"$NEW_VERSION\" }/" Cargo.toml
sed -i "s/huginn-net-tls = { path = \"huginn-net-tls\", version = \".*\" }/huginn-net-tls = { path = \"huginn-net-tls\", version = \"$NEW_VERSION\" }/" Cargo.toml

INTERNAL_CRATES=(
    "huginn-net-db"
)

PUBLIC_CRATES=(
    "huginn-net-tcp" 
    "huginn-net-http"
    "huginn-net-tls"
    "huginn-net"
)

echo "Updating internal crate versions..."
for crate in "${INTERNAL_CRATES[@]}"; do
    sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" "$crate/Cargo.toml"
done

echo "Updating public crate versions..."
for crate in "${PUBLIC_CRATES[@]}"; do
    sed -i "s/^version = \".*\"/version = \"$NEW_VERSION\"/" "$crate/Cargo.toml"
done

echo "Versions updated to $NEW_VERSION"

echo "Verifying compilation..."
cargo check --workspace

echo "To publish public crates, run:"
for crate in "${PUBLIC_CRATES[@]}"; do
    echo "cargo publish -p $crate"
done

echo "To create tags, run:"
echo "git tag -a v$NEW_VERSION -m 'Release v$NEW_VERSION: Public crates synchronized'"
echo "git push origin v$NEW_VERSION"
