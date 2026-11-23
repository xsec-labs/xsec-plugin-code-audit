#!/usr/bin/env bash
# Keeps skills/security-audit/ a verbatim copy of cloudflare/security-audit-skill at a pinned commit.
#
#   scripts/sync-upstream-skill.sh check            verify the files against UPSTREAM.json (no network)
#   scripts/sync-upstream-skill.sh sync <ref>       download <ref> (commit, tag or branch), replace the files and
#                                                   rewrite UPSTREAM.json; review the diff, then re-run the golden
#                                                   corpus: node scripts/gen-golden.cjs skills/security-audit
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dir="$root/skills/security-audit"
manifest="$dir/UPSTREAM.json"
raw="https://raw.githubusercontent.com/cloudflare/security-audit-skill"

sha() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

case "${1:-}" in
check)
  fail=0
  while IFS=$'\t' read -r name want; do
    [ -f "$dir/$name" ] || { echo "MISSING $name"; fail=1; continue; }
    got="$(sha "$dir/$name")"
    [ "$got" = "$want" ] || { echo "CHANGED $name"; fail=1; }
  done < <(python3 -c 'import json,sys; [print(k+"\t"+v) for k,v in json.load(open(sys.argv[1]))["files"].items()]' "$manifest")
  extra="$(cd "$dir" && ls | grep -vxF -e UPSTREAM.json -e LICENSE | while read -r f; do python3 -c 'import json,sys; sys.exit(0 if sys.argv[2] in json.load(open(sys.argv[1]))["files"] else 1)' "$manifest" "$f" || echo "$f"; done)"
  [ -z "$extra" ] || { echo "UNLISTED $extra"; fail=1; }
  [ "$fail" = 0 ] && echo "skills/security-audit matches UPSTREAM.json" || exit 1
  ;;
sync)
  ref="${2:?usage: sync <ref>}"
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  names="$(python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["files"]))' "$manifest")"
  curl -fsS "$raw/$ref/LICENSE" -o "$tmp/LICENSE"
  for n in $names; do curl -fsS "$raw/$ref/skills/security-audit/$n" -o "$tmp/$n"; done
  cp "$tmp"/* "$dir/"
  python3 - "$dir" "$ref" "$manifest" <<'PY'
import hashlib, json, os, sys
d, ref, manifest = sys.argv[1:4]
old = json.load(open(manifest))
files = {n: hashlib.sha256(open(os.path.join(d, n), "rb").read()).hexdigest() for n in sorted(old["files"])}
old.update({"ref": ref, "files": files})
open(manifest, "w").write(json.dumps(old, indent=2) + "\n")
PY
  echo "synced to $ref; review the diff and re-record the golden corpus"
  ;;
*) echo "usage: $0 check | sync <ref>" >&2; exit 2 ;;
esac
