#!/usr/bin/env bash
# Builds the plugin bundle inside golang and node containers, so no host toolchain is needed.
# Usage: build/docker-build.sh   (output: dist/<plugin id>-<version>.tar.gz)
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
CACHE="${BUILD_CACHE_DIR:-${TMPDIR:-/var/tmp}/mattermost-plugin-mcp-cache}"
mkdir -p "$CACHE/go"
UIDGID="$(id -u):$(id -g)"

go_run() {
    docker run --rm -u "$UIDGID" -e HOME=/tmp -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod \
        -v "$CACHE/go:/cache" -v "$ROOT:/src" -w /src golang:1.26 sh -euc "$1"
}

go_run 'CGO_ENABLED=0 go build -o build/bin/manifest ./build/manifest && ./build/bin/manifest apply'
go_run 'cd server && rm -rf dist && for arch in amd64 arm64; do CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -trimpath -o dist/plugin-linux-$arch .; done'

ID="$(./build/bin/manifest id)"
VERSION="$(./build/bin/manifest version)"
docker run --rm -u "$UIDGID" -e HOME=/tmp -v "$ROOT:/src" -w /src/webapp node:24 sh -euc 'npm run build'
rm -rf dist && mkdir -p "dist/$ID/server" "dist/$ID/webapp"
./build/bin/manifest dist
cp -r server/dist "dist/$ID/server/"
cp -r webapp/dist "dist/$ID/webapp/"
cp LICENSE NOTICE "dist/$ID/"
tar -C dist -czf "dist/$ID-$VERSION.tar.gz" "$ID"
echo "plugin built at: dist/$ID-$VERSION.tar.gz"
