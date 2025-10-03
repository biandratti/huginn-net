# Release Process

## Update versions
```bash
./scripts/update-version.sh <x.y.z>
```

## Publish crates
```bash
cargo publish -p huginn-net-tcp
cargo publish -p huginn-net-http
cargo publish -p huginn-net-tls
cargo publish -p huginn-net
```

## Create release tag
```bash
git tag -a v<x.y.z> -m 'Release v<x.y.z>'
git push origin v<x.y.z>
```
