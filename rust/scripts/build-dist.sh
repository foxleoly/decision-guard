#!/usr/bin/env bash
# Builds the release binary for THIS machine's target and refreshes ../dist/: the binary as
# dist/decision-guard-<target-triple> and dist/SHA256SUMS for every file in dist/ except README.md.
# Other targets must be built on a machine of that target; run this script there and commit the result.
set -euo pipefail

RUST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$RUST/../dist"
# Dependency panic locations are baked in as absolute paths, which would leak the builder's home directory into a
# shippable artifact. --remap-path-prefix is a rustc option (this machine has no rust-lld executable at all); it is
# passed through RUSTFLAGS so every crate gets it. The destinations are relative, so the binary carries no path that
# reveals where it was built; the check at the end of this script fails the build if one slips through anyway.
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=./cargo --remap-path-prefix=$RUST=./"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/dg-target}"

triple=$(rustc -vV | sed -n 's/^host: //p')
[ -n "$triple" ] || { echo "error: cannot read the host triple from rustc -vV" >&2; exit 1; }

cargo build --release --manifest-path "$RUST/Cargo.toml"
mkdir -p "$DIST"
cp "$CARGO_TARGET_DIR/release/decision-guard" "$DIST/decision-guard-$triple"
command -v strip >/dev/null && strip "$DIST/decision-guard-$triple" || true # the release profile already strips; harmless if not
chmod 755 "$DIST/decision-guard-$triple"

cd "$DIST"
if command -v sha256sum >/dev/null; then sums() { sha256sum "$@"; }; else sums() { shasum -a 256 "$@"; }; fi
sums decision-guard-* > SHA256SUMS
ls -l decision-guard-*
cat SHA256SUMS
# No absolute path of this machine may end up in the shipped binary.
if strings -a "decision-guard-$triple" | grep -q "/Users/\|$HOME"; then
	echo "error: decision-guard-$triple still embeds a local path:" >&2
	strings -a "decision-guard-$triple" | grep "/Users/\|$HOME" | head -3 >&2
	exit 1
fi
echo "ok: no local paths embedded"
