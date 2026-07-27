#!/bin/sh
# One command to put the gateway on a Linux or macOS machine, and the same one
# to upgrade it.
#
#   curl -fsSL https://raw.githubusercontent.com/ivanzzeth/trust-proxy/main/scripts/install.sh | sudo sh
#
# It downloads the release for this platform, puts the CLI on PATH, and runs
# `trust-proxy install` — which registers the system service, starts it, enables
# it at boot, and hands the first admin's API key to whoever invoked sudo.
# Re-running it upgrades: `install` replaces the service's copy of the binary and
# restarts it, leaving policy and accounts alone.
#
# Why this exists: the alternative is uname, a version, a URL, tar, and a install
# -m 0755, typed again at every release. Five chances to get it wrong, and the
# one that matters — running the tarball's binary from inside the unpacked
# directory — used to seed the machine's config from that directory.
#
# POSIX sh, not bash: this runs on whatever a fresh server has.
#
# Environment:
#   TP_VERSION=v0.10.1   pin a version (default: the latest release)
#   TP_TARBALL=/path     install from a local tarball instead of downloading
#   TP_BINDIR=/usr/local/bin
#   TP_NO_SERVICE=1      unpack and put the CLI on PATH, but do not install the
#                        service (for looking before leaping)

set -eu

REPO=ivanzzeth/trust-proxy
BINDIR=${TP_BINDIR:-/usr/local/bin}

say() { printf '\033[36m==>\033[0m %s\n' "$*"; }
die() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required and not installed"; }

# Root is needed for the service, for /usr/local/bin, and for the machine-wide
# data directory. Checked first: a download that then cannot install is a waste
# of somebody's bandwidth and patience.
[ "$(id -u)" = 0 ] || die "run this with sudo (it installs a system service)"

case "$(uname -s)" in
  Linux)  os=linux ;;
  Darwin) os=darwin ;;
  *)      die "unsupported OS $(uname -s) — Linux and macOS have releases; Windows is a manual download" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *)             die "unsupported architecture $(uname -m)" ;;
esac
# There is no darwin/amd64 release; say so rather than 404ing.
[ "$os$arch" = darwinamd64 ] && die "there is no darwin/amd64 release — build from source (make build)"

work=$(mktemp -d)
# shellcheck disable=SC2064 # expand $work now, not at exit
trap "rm -rf '$work'" EXIT INT TERM

if [ -n "${TP_TARBALL:-}" ]; then
  [ -f "$TP_TARBALL" ] || die "no tarball at $TP_TARBALL"
  say "installing from $TP_TARBALL"
  tar xzf "$TP_TARBALL" -C "$work"
else
  need curl
  need tar
  version=${TP_VERSION:-}
  if [ -z "$version" ]; then
    say "looking up the latest release"
    # The redirect target of /releases/latest ends in the tag. Parsing that beats
    # the API, which rate-limits unauthenticated callers — and a rate limit at
    # install time looks exactly like "the project is broken".
    version=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
      "https://github.com/$REPO/releases/latest" 2>/dev/null | sed 's|.*/tag/||')
    [ -n "$version" ] || die "could not work out the latest version; pass TP_VERSION=vX.Y.Z"
  fi
  case "$version" in v*) ;; *) version="v$version" ;; esac

  pkg="trust-proxy_${version}_${os}_${arch}.tar.gz"
  url="https://github.com/$REPO/releases/download/$version/$pkg"
  say "downloading $version for $os/$arch"
  curl -fL --progress-bar -o "$work/$pkg" "$url" \
    || die "could not download $url — check the version exists for $os/$arch"
  tar xzf "$work/$pkg" -C "$work" || die "the download is not a readable tarball"
fi

bin=$(find "$work" -type f -name trust-proxy -perm -u+x | head -1)
[ -n "$bin" ] || die "no trust-proxy binary in the package"

# Sanity-check what was downloaded before handing it root. A truncated or
# mismatched download would otherwise be discovered by systemd, at boot.
"$bin" version >/dev/null 2>&1 || die "the downloaded binary does not run on this machine"
if ! "$bin" version | grep -q 'console: *embedded'; then
  die "this build has no console in it, and \`install\` will refuse it — wrong artifact?"
fi

say "installing the CLI to $BINDIR/trust-proxy"
install -d "$BINDIR"
# Not `cp` onto a running binary: replacing the file a process is executing is
# ETXTBSY on some systems. install(1) unlinks first.
install -m 0755 "$bin" "$BINDIR/trust-proxy"

if [ "${TP_NO_SERVICE:-}" = 1 ]; then
  say "TP_NO_SERVICE=1 — stopping here. Set it up with: sudo trust-proxy install"
  exit 0
fi

# From the installed path, not from the unpacked directory: `install` copies
# whichever binary it is running to the managed location, and running it out of a
# temporary directory is how you get a service pointing at something that has
# been deleted.
say "setting up the system service"
"$BINDIR/trust-proxy" install

cat <<EOF

Done. The gateway is a system service now: it runs as root, starts at boot, and
restarts if it dies.

  trust-proxy status      what it is doing
  trust-proxy env         where everything is, and what state this machine is in
  sudo trust-proxy uninstall   remove the service (your config stays)

Upgrading later is this same command again.
EOF
