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

.PHONY: help run app build build-ui build-go build-embed build-app check-build-owner tidy \
	e2e-fleet e2e-linux e2e-policy e2e-dataplane e2e-macos e2e-desktop dashboard dashboard-dev dashboard-test \
	deps clean e2e redeploy desktop desktop-dev desktop-sidecar app-service-hint \
	release version-check

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
	@echo "  make app          build the app, install it, and open it"
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

# Where `make app` puts the built bundle. Override APP_DIR to install elsewhere.
#
# APP_DIR is a variable of its own rather than $(dir $(APP_INSTALL)): make's $(dir)
# splits on whitespace, and "Trust Proxy.app" is two words to it — which turned the
# destination into "/Applications/ ./" and copied the bundle nowhere useful.
APP_NAME    ?= Trust Proxy.app
APP_DIR     ?= /Applications
APP_BUNDLE   = desktop/src-tauri/target/release/bundle/macos/$(APP_NAME)
APP_INSTALL  = $(APP_DIR)/$(APP_NAME)

## Build the app, install it, and open it — the one command for "use the app".
##
## It replaces the installed copy first, because `open` on a bundle that is
## already running just re-focuses the running process: you would be looking at
## the old build and believe it was the new one. That is how an .app from before
## the ports were renumbered stayed on screen probing an address nobody answered.
app: build-app
ifeq ($(shell uname -s),Darwin)
	@# Quit the running copy. This only ends the window and any gateway that
	@# window started; a gateway owned by launchd is untouched, which is the point
	@# of having it owned by launchd.
	@osascript -e 'quit app "Trust Proxy"' >/dev/null 2>&1 || true
	@pkill -f "$(APP_INSTALL)/Contents/MacOS/trust-proxy-desktop" >/dev/null 2>&1 || true
	@# The bundle is only worth installing if its gateway carries the console: a
	@# sidecar without one serves "dashboard not built" on every page, and there is
	@# no dashboard/dist next to a .app for it to fall back to. The dependency
	@# chain (app -> build-app -> desktop-sidecar -> build-embed) already ensures
	@# this; the check is here because "the chain is right" is what everyone
	@# believes right up until it is not.
	@"$(APP_BUNDLE)/Contents/MacOS/trust-proxy" version --json | grep -q '"console": *true' || { \
		echo "the bundled gateway has no console in it — refusing to install a blank app"; \
		echo "  (that binary should come from build-embed; check desktop-sidecar)"; exit 1; }
	@# Only ever delete something that is actually our bundle: APP_INSTALL is
	@# overridable, and a typo must not take a directory with it.
	@if [ -e "$(APP_INSTALL)" ] && [ ! -x "$(APP_INSTALL)/Contents/MacOS/trust-proxy-desktop" ]; then \
		echo "refusing to replace $(APP_INSTALL): that is not a trust-proxy bundle"; exit 1; fi
	@# An installed copy owned by root (someone ran this under sudo once) cannot be
	@# replaced, and `rm -rf` would spray three permission errors instead of saying so.
	@if [ -e "$(APP_INSTALL)" ] && [ ! -O "$(APP_INSTALL)" ]; then \
		echo "$(APP_INSTALL) is owned by someone else — an earlier sudo install left it that way."; \
		echo "remove it once, then re-run this:"; \
		echo "    sudo rm -rf \"$(APP_INSTALL)\""; exit 1; fi
	@rm -rf "$(APP_INSTALL)"
	@cp -R "$(APP_BUNDLE)" "$(APP_DIR)/" || { \
		echo "could not write to $(APP_DIR) — install it by hand:"; \
		echo "  cp -R \"$(APP_BUNDLE)\" \"$(APP_DIR)/\""; exit 1; }
	@# cp reports success for some partial copies; the thing we are about to open
	@# has to actually be there.
	@test -x "$(APP_INSTALL)/Contents/MacOS/trust-proxy-desktop" || { \
		echo "the copy did not land at $(APP_INSTALL)"; exit 1; }
	@echo "==> installed $(APP_INSTALL)"
	@$(MAKE) --no-print-directory app-service-hint
	@open "$(APP_INSTALL)"
else
	@echo "==> launching the shell (bundles for this platform are in desktop/src-tauri/target/release/bundle/)"
	./desktop/src-tauri/target/release/trust-proxy-desktop
endif

# If a system service is installed but runs an older binary than the one just
# built, the app will attach to *that* gateway — so the window shows the old
# code and nothing about it looks wrong. Say it, with the command that fixes it.
app-service-hint:
	@# The table output, not --json: the JSON is pretty-printed across lines, so a
	@# substring match on it silently never fires — which is exactly what this
	@# hint existing is supposed to prevent.
	@status=$$(./trust-proxy service status 2>/dev/null || true); \
	prog=$$(printf '%s\n' "$$status" | sed -n 's/^program:[[:space:]]*//p'); \
	if printf '%s\n' "$$status" | grep -q '^installed:.*true' && [ -x "$$prog" ] && \
	   [ "$$("$$prog" --version 2>/dev/null)" != "$$(./trust-proxy --version 2>/dev/null)" ]; then \
		echo "==> note: the installed service still runs an older gateway:"; \
		echo "      $$prog ($$("$$prog" --version 2>/dev/null | awk '{print $$NF}'))"; \
		echo "    the app attaches to that one, so the window would show the old code."; \
		echo "    update it too:  sudo ./trust-proxy service install --mode tun -y"; \
	fi

## Boot the gateway (config: <data>/config.json, seeded on first run)
run: build-embed
	./trust-proxy serve

## Fail early when the tree holds build output this user cannot replace.
##
## One `sudo make` poisons every later build: vite empties dashboard/dist and
## Tauri removes the old .app, and neither can touch root-owned files. The error
## you get otherwise names a file nobody recognises, three layers into a bundler.
## Only the *daemon* needs root; building never does.
check-build-owner:
	@if [ "$$(id -u)" = "0" ]; then \
		echo "don't build as root: it leaves root-owned files in the tree that your next"; \
		echo "ordinary build cannot replace. Build as yourself; only the daemon needs root"; \
		echo "(sudo ./trust-proxy serve / sudo ./trust-proxy service install)."; exit 1; fi
	@bad=$$(find dashboard/dist desktop/src-tauri/target/release/bundle \
		! -user "$$(id -un)" -print -quit 2>/dev/null); \
	if [ -n "$$bad" ]; then \
		echo "build output owned by someone else (a previous sudo build), e.g."; \
		echo "    $$bad"; \
		echo "the bundlers have to delete these and cannot. Remove them once:"; \
		echo "    sudo rm -rf dashboard/dist desktop/src-tauri/target/release/bundle"; \
		exit 1; fi

## Just the console -> dashboard/dist
build-ui: check-build-owner
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

## Cut a release: write the version everywhere it has to be a literal, run the
## gates, commit and tag. `make release VERSION=0.10.0` (add PUSH=1 to push,
## which is what actually publishes). `make version-check` just reports.
##
## The Go binary takes its version from `git describe`, so only the desktop
## shell needs this — but its number lives in three files, and three files is
## three chances to update two of them (they had reached 0.7.0 / 0.9.0 / 0.7.0).
## cmd/version_test.go fails if they disagree, so this is not optional hygiene.
release:
	@test -n "$(VERSION)" || { echo "usage: make release VERSION=0.10.0 [PUSH=1]"; exit 1; }
	@scripts/release.sh "$(VERSION)" $(if $(PUSH),--push,)

version-check:
	@scripts/release.sh --check

tidy:
	go mod tidy

## macOS e2e in a tart VM: the launchd service lifecycle and TUN capture with its
## dead-man's switch — the two things that need a real macOS host and root, and
## that must never be tried on the developer's own machine. Skips when tart, the
## VM or sshpass are missing (TP_TART_VM overrides the VM name).
e2e-macos:
	go test -count=1 -tags tart_e2e -run 'TestMacOS' -v -timeout 15m ./test/

## Multi-gateway e2e in containers: origin + gateway + client, no internet needed.
## Verifies the shape the feature exists for — a remote gateway holds the policy
## and a local machine egresses through it with its own account — and cleans up.
e2e-fleet:
	go test -count=1 -tags docker_e2e -run TestFleetGatewayAsExit -v -timeout 10m ./test/

## What the gateway does to *packets*, on a real install: default-deny, Permit vs
## Deny, the Route/Permit axis split, Global mode's floor, the mode dead-man's
## switch, policy surviving restart and in-place upgrade, key rotation on login.
e2e-dataplane:
	go test -count=1 -tags docker_e2e -run 'TestLinux(DefaultDeny|GlobalMode|GuardedMode|PolicySurvives|LoginRotates|FreshInstallResolves|UpgradeHealsTheOldDNS|SplitWorksWithNo)' -v -timeout 20m ./test/

## Every command that rewrites policy, under a real systemd: each one rebuilds
## the sing-box config, and a config the box refuses is a gateway that enforces
## nothing. Asserts the change took *and* that the data plane survived it.
e2e-policy:
	go test -count=1 -tags docker_e2e -run TestLinuxPolicyRebuilds -v -timeout 15m ./test/

## Linux service lifecycle under a real systemd (privileged container, pid 1 =
## systemd): install, restart after kill -9, TUN, and a clean uninstall.
e2e-linux:
	go test -count=1 -tags docker_e2e -run TestLinuxSystemdServiceLifecycle -v -timeout 15m ./test/

## What is inside the shipped .app, and does it still match the gateway: the
## shell's default API address vs the gateway's, and whether the bundled sidecar
## actually carries a console. Both are the drift that let a stale bundle sit on
## the splash screen forever. Skips when there is no bundle (TP_APP_BUNDLE to
## point at one; TP_DESKTOP_GUI=1 also runs the attach test, which opens a window).
e2e-desktop:
	go test -count=1 -tags desktop_e2e -run TestDesktop -v -timeout 10m ./test/

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

build-app: check-build-owner desktop-sidecar
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
