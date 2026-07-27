SING_BOX_DIR := third_party/sing-box

# Build tags:
#   with_clash_api -> Clash REST/WS API our backend consumes (pkg/clash)
#   with_quic      -> Hysteria2 / TUIC / QUIC (common in real subscriptions)
#   with_utls      -> uTLS fingerprints (vless reality/tls fp)
#   with_grpc      -> full gRPC transport (there is a lite fallback without it)
#   with_wireguard -> WireGuard exit endpoints
#   with_tailscale -> Tailscale exit endpoints (big dep; ~+18MB binary)
TAGS ?= with_clash_api with_quic with_utls with_grpc with_gvisor with_wireguard with_tailscale

# Stamp the binary with the tag it was built from, so `trust-proxy -v` reports
# something other than "dev" (falls back to the commit when tags are absent).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -X github.com/ivanzzeth/trust-proxy/cmd.version=$(VERSION)

.PHONY: help run build build-ui build-go build-embed build-app tidy \
	e2e-fleet e2e-linux e2e-macos e2e-desktop dashboard dashboard-dev dashboard-test \
	deps clean e2e redeploy desktop desktop-dev desktop-sidecar

# `make` on its own lists what there is to run.
.DEFAULT_GOAL := help

# Redeploy defaults (override: make redeploy MODE=manual)
DATA_DIR  ?= $(HOME)/.trust-proxy
CONFIG    ?=
MODE      ?= tun
PID_FILE  ?= $(DATA_DIR)/serve.pid

## Show the targets and what they are for (this is what plain `make` does).
##
## A target's summary is the FIRST line of its comment block; the rest is
## reasoning, which belongs in this file and not in the listing. The awk lives in
## the recipe rather than in a variable because a `#` in a make variable starts a
## make comment and eats the pattern.
help:
	@echo "trust-proxy — the ones you usually want:"
	@echo ""
	@echo "  make build        everything, the way it ships: console + single binary + app"
	@echo "  make run          build the single binary and start the gateway"
	@echo "  make deps         first time: fetch the sing-box submodule"
	@echo ""
	@echo "  build-* = the individual pieces, when you know which one you need:"
	@awk '/^## /{ if (!blk) { c = substr($$0,4); blk = 1 } next } { blk = 0 } /^build-[a-z-]+:/{ printf "    %-14s %s\n", substr($$0,1,index($$0,":")-1), c }' $(MAKEFILE_LIST)
	@echo ""
	@echo "  tests (each skips when its dependency is not installed):"
	@awk '/^## /{ if (!blk) { c = substr($$0,4); blk = 1 } next } { blk = 0 } /^(e2e[a-z-]*|dashboard-test):/{ printf "    %-14s %s\n", substr($$0,1,index($$0,":")-1), c }' $(MAKEFILE_LIST)
	@echo ""
	@echo "  everything else: run deps tidy clean redeploy dashboard-dev desktop-dev desktop-sidecar"

## Everything, built the way it ships: console -> single binary -> desktop app.
## Plain `build` is deliberately the *safe* one. The build-* targets below are the
## individual pieces; reach for them when you know which piece you want.
##
## Why the default is the whole thing: `build` used to produce a binary with no
## console in it, which looks fine until you install it as a service and every
## page says "dashboard not built". The name you type without thinking should be
## the one that cannot do that.
build: build-embed
	@if command -v cargo >/dev/null 2>&1; then \
		$(MAKE) --no-print-directory build-app; \
	else \
		echo "==> desktop app skipped: no cargo here (fine on a server)"; \
		echo "    ./trust-proxy is complete and has the console embedded"; \
		echo "    to build the app too: install Rust, then make build-app"; \
	fi

## Boot the gateway (config: <data>/config.json, seeded on first run)
run: build-embed
	./trust-proxy serve

## Just the console -> dashboard/dist
build-ui:
	cd dashboard && corepack pnpm install && corepack pnpm build

## Just the Go binary, no console inside it (fast inner loop; pair with
## `make dashboard-dev`, or serve an existing dashboard/dist from disk).
## Not what you want to install as a service — `service install` refuses it.
build-go:
	go build $(if $(TAGS),-tags "$(TAGS)",) -ldflags "$(LDFLAGS)" -o trust-proxy .

## Single self-contained binary: build the console then embed it (embed_ui)
build-embed: build-ui
	go build -tags "$(TAGS) embed_ui" -ldflags "$(LDFLAGS)" -o trust-proxy .

## Build embedded UI + binary, then restart the daemon.
## One sudo wraps stop+start (one password). Override MODE=manual to skip root if unused.
redeploy: build-embed
	@echo "==> restarting serve (data=$(DATA_DIR) mode=$(MODE))"
	sudo sh -c '$(CURDIR)/trust-proxy proxy stop --pid "$(PID_FILE)" 2>/dev/null || true; \
		sleep 1; \
		cd "$(CURDIR)" && ./trust-proxy serve --daemon --data "$(DATA_DIR)" $(if $(CONFIG),-c "$(CONFIG)",) --mode "$(MODE)"'
	@echo "==> done. UI http://127.0.0.1:21585/  (hard-refresh if needed)"
	@echo "    stop:  sudo $(CURDIR)/trust-proxy proxy stop --pid $(PID_FILE)"

tidy:
	go mod tidy

## macOS e2e in a tart VM: the launchd service lifecycle and TUN capture with its
## dead-man's switch — the two things that need a real macOS host and root, and
## that must never be tried on the developer's own machine. Skips when tart, the
## VM or sshpass are missing (TP_TART_VM overrides the VM name).
e2e-macos:
	go test -tags tart_e2e -run 'TestMacOS' -v -timeout 15m ./test/

## Multi-gateway e2e in containers: origin + gateway + client, no internet needed.
## Verifies the shape the feature exists for — a remote gateway holds the policy
## and a local machine egresses through it with its own account — and cleans up.
e2e-fleet:
	go test -tags docker_e2e -run TestFleetGatewayAsExit -v -timeout 10m ./test/

## Linux service lifecycle under a real systemd (privileged container, pid 1 =
## systemd): install, restart after kill -9, TUN, and a clean uninstall.
e2e-linux:
	go test -tags docker_e2e -run TestLinuxSystemdServiceLifecycle -v -timeout 15m ./test/

## What is inside the shipped .app, and does it still match the gateway: the
## shell's default API address vs the gateway's, and whether the bundled sidecar
## actually carries a console. Both are the drift that let a stale bundle sit on
## the splash screen forever. Skips when there is no bundle (TP_APP_BUNDLE to
## point at one; TP_DESKTOP_GUI=1 also runs the attach test, which opens a window).
e2e-desktop:
	go test -tags desktop_e2e -run TestDesktop -v -timeout 10m ./test/

## Run the end-to-end proxy protocol test (self-hosted server <-> client tunnel)
e2e:
	go test $(if $(TAGS),-tags "$(TAGS)",) -run TestProxyE2E -v ./internal/proxygen/

## First-time setup: fetch the sing-box submodule
deps:
	git submodule update --init --recursive

## Frontend unit tests (vitest, jsdom): pages rendered against a mocked API
dashboard-test:
	cd dashboard && corepack pnpm test

## Run the dashboard dev server (Vite at :3100, proxies /api -> :21585)
dashboard-dev:
	cd dashboard && corepack pnpm dev

## --- desktop shell (macOS / Linux / Windows) ---------------------------------
## The sidecar MUST be the embed_ui build: inside a .app there is no
## dashboard/dist on disk to serve the console from.
DESKTOP_TRIPLE ?= $(shell rustc -vV | sed -n 's/^host: //p')
## Tauri matches the sidecar by "<name>-<triple>", keeping the host's executable
## suffix — so a Windows build must be trust-proxy-<triple>.exe or the bundle ends
## up with no gateway in it.
DESKTOP_EXE ?= $(if $(findstring windows,$(DESKTOP_TRIPLE)),.exe,)

desktop-sidecar: build-embed
	mkdir -p desktop/src-tauri/binaries
	cp trust-proxy$(DESKTOP_EXE) desktop/src-tauri/binaries/trust-proxy-$(DESKTOP_TRIPLE)$(DESKTOP_EXE)

## Build Trust Proxy.app (+ dmg) with the gateway bundled as a sidecar.
## Ad-hoc signs by default ("-"): without it Tauri leaves the bundle unsealed and
## even `spctl` cannot assess it ("code has no resources but signature indicates
## they must be present"). Ad-hoc is not notarization — Gatekeeper still asks the
## user once — but it makes the bundle well-formed. Set APPLE_SIGNING_IDENTITY to
## a real "Developer ID Application: …" to sign for distribution.
APPLE_SIGNING_IDENTITY ?= -

build-app: desktop-sidecar
	cd desktop && corepack pnpm install && APPLE_SIGNING_IDENTITY="$(APPLE_SIGNING_IDENTITY)" corepack pnpm build

## Older names, kept because fingers remember them.
desktop: build-app
dashboard: build-ui

## Run the shell against a dev build (attaches to a running gateway if there is one)
desktop-dev: desktop-sidecar
	cd desktop && corepack pnpm install && corepack pnpm dev

clean:
	rm -f trust-proxy
	rm -rf desktop/src-tauri/binaries desktop/src-tauri/target
