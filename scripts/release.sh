#!/usr/bin/env bash
# Cut a release: one version, written everywhere it has to be literal.
#
# The Go binary does not need this — its version comes from `git describe` at
# build time (Makefile) and from the tag in CI. The desktop shell does: a
# bundler cannot read a git tag, so the number has to sit in three files, and
# three files with a number in them is three chances to forget one. They had
# already drifted to 0.7.0 / 0.9.0 / 0.7.0 before anyone noticed, which is not a
# failure of discipline — it is what happens when the only thing keeping four
# places in step is somebody remembering.
#
# So: this script is the only writer, and version_test.go fails the build if the
# files disagree. A script nobody is forced to run drifts exactly as fast as no
# script at all.
#
#   scripts/release.sh 0.10.0            # write, verify, test, commit, tag
#   scripts/release.sh 0.10.0 --push     # …and push the branch and the tag
#   scripts/release.sh --check           # just say whether the files agree
#
# Pushing a v* tag makes the release workflow publish a GitHub Release, so
# --push is opt-in and never the default.

set -euo pipefail
cd "$(dirname "$0")/.."

# The files that must carry a literal version, and how to rewrite each.
PKG_JSON=desktop/package.json
TAURI_JSON=desktop/src-tauri/tauri.conf.json
CARGO_TOML=desktop/src-tauri/Cargo.toml

die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
note() { printf '\033[36m==>\033[0m %s\n' "$*"; }

read_versions() {
  # Deliberately the same shape of extraction the files use, not a JSON parser:
  # there is no jq on every machine and the fields are ours.
  V_PKG=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$PKG_JSON" | head -1)
  V_TAURI=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$TAURI_JSON" | head -1)
  V_CARGO=$(sed -n 's/^version = "\([^"]*\)".*/\1/p' "$CARGO_TOML" | head -1)
}

check() {
  read_versions
  printf '  %-40s %s\n' "$PKG_JSON" "$V_PKG"
  printf '  %-40s %s\n' "$TAURI_JSON" "$V_TAURI"
  printf '  %-40s %s\n' "$CARGO_TOML" "$V_CARGO"
  [ -n "$V_PKG" ] && [ -n "$V_TAURI" ] && [ -n "$V_CARGO" ] \
    || die "could not read a version out of one of those files"
  [ "$V_PKG" = "$V_TAURI" ] && [ "$V_PKG" = "$V_CARGO" ] \
    || die "the desktop versions disagree — run: scripts/release.sh <version>"
  note "desktop version: $V_PKG"
}

write_version() {
  local v=$1
  # sed -i differs between GNU and BSD; write to a temp and move, which is the
  # same everywhere and is atomic besides.
  local tmp
  tmp=$(mktemp)
  sed "1,/\"version\"/ s/\(\"version\": *\)\"[^\"]*\"/\1\"$v\"/" "$PKG_JSON" >"$tmp" && mv "$tmp" "$PKG_JSON"
  tmp=$(mktemp)
  sed "1,/\"version\"/ s/\(\"version\": *\)\"[^\"]*\"/\1\"$v\"/" "$TAURI_JSON" >"$tmp" && mv "$tmp" "$TAURI_JSON"
  tmp=$(mktemp)
  sed "1,/^version = / s/^version = \"[^\"]*\"/version = \"$v\"/" "$CARGO_TOML" >"$tmp" && mv "$tmp" "$CARGO_TOML"
}

gates() {
  note "go vet / test"
  go vet ./cmd/... ./internal/... ./pkg/...
  go test ./cmd/... ./internal/... ./pkg/...
  note "cross-compile (a release ships four targets; only one gets built by default)"
  local tags="with_clash_api with_quic with_utls with_grpc with_gvisor with_wireguard with_tailscale"
  for target in linux/amd64 linux/arm64 windows/amd64 darwin/arm64; do
    GOOS="${target%/*}" GOARCH="${target#*/}" CGO_ENABLED=0 \
      go build -tags "$tags" -o /dev/null . || die "$target does not build"
    echo "    $target"
  done
  note "console: typecheck and tests"
  (cd dashboard && npx tsc --noEmit && corepack pnpm test --run >/dev/null)
  note "shell: cargo test (its Linux elevation is behind cfg, so this is the only thing that compiles it here)"
  (cd desktop/src-tauri && cargo test --quiet >/dev/null)
  note "engine selftest"
  make --no-print-directory build-go >/dev/null
  # Captured rather than silenced: the selftest narrates every gateway rebuild on
  # stderr, which buries the one line that matters, but throwing it away would
  # leave a failure with nothing to look at.
  local log
  log=$(mktemp)
  if ! ./trust-proxy selftest >"$log" 2>&1; then
    tail -30 "$log" >&2
    die "selftest failed (full output: $log)"
  fi
  grep -E '^[0-9]+ passed' "$log" | sed 's/^/    /' || true
  rm -f "$log"
}

# ---- arguments -------------------------------------------------------------

VERSION=""
PUSH=0
SKIP_TESTS=0
for arg in "$@"; do
  case "$arg" in
    --check) check; exit 0 ;;
    --push) PUSH=1 ;;
    --skip-tests) SKIP_TESTS=1 ;;
    -*) die "unknown flag $arg" ;;
    *) VERSION="${arg#v}" ;; # accept 0.10.0 or v0.10.0
  esac
done
[ -n "$VERSION" ] || die "usage: scripts/release.sh <version> [--push] [--skip-tests] | --check"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
  || die "'$VERSION' is not a semver like 0.10.0"

TAG="v$VERSION"
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null && die "$TAG already exists"

# A dirty tree means the tag would point at something that is not what was
# tested, and nobody would be able to tell afterwards.
[ -z "$(git status --porcelain)" ] || {
  git status --short
  die "working tree is not clean; commit or stash first"
}

note "writing $VERSION into the desktop files"
write_version "$VERSION"
# Cargo.lock records the package's own version, so it moves too. --offline: this
# must not turn into a dependency update on the way to a tag.
(cd desktop/src-tauri && cargo update --offline -p trust-proxy-desktop --precise "$VERSION" >/dev/null 2>&1 \
  || cargo check --quiet >/dev/null 2>&1 || true)
check

if [ "$SKIP_TESTS" = 0 ]; then
  gates
else
  note "skipping tests (--skip-tests)"
fi

if [ -n "$(git status --porcelain)" ]; then
  git add "$PKG_JSON" "$TAURI_JSON" "$CARGO_TOML" desktop/src-tauri/Cargo.lock
  git commit -q -m "chore: version $VERSION"
  note "committed the version bump"
fi

git tag -a "$TAG" -m "$TAG"
note "tagged $TAG"

if [ "$PUSH" = 1 ]; then
  branch=$(git rev-parse --abbrev-ref HEAD)
  note "pushing $branch and $TAG (this makes the release workflow publish)"
  git push origin "$branch"
  git push origin "$TAG"
else
  cat <<EOF

Not pushed. Pushing the tag is what publishes a release:

    git push origin $(git rev-parse --abbrev-ref HEAD)
    git push origin $TAG
EOF
fi
