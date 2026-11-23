#!/usr/bin/env bash
# Builds the MCP sidecar. usage: scripts/build-sidecar.sh [GOOS GOARCH]   (default: the host)
# Output: dist/<goos>-<goarch>/code-audit-mcp[.exe]. No cgo; the release recipe in xsec-plugins builds the same way.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
goos="${1:-$(go env GOOS)}"; goarch="${2:-$(go env GOARCH)}"
ext=""; [ "$goos" = windows ] && ext=".exe"
out="$root/dist/$goos-$goarch/code-audit-mcp$ext"
mkdir -p "$(dirname "$out")"
(cd "$root/sidecar" && CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath -ldflags "-s -w" -o "$out" ./cmd/code-audit-mcp)
echo "$out"
