SING_BOX_DIR := third_party/sing-box
WEBUI_DIR    := webui

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

.PHONY: run build build-embed tidy webui webui-dev dashboard dashboard-dev dashboard-test deps clean e2e redeploy desktop desktop-dev desktop-sidecar

# Redeploy defaults (override: make redeploy MODE=manual)
DATA_DIR  ?= $(HOME)/.trust-proxy
CONFIG    ?= configs/config.json
MODE      ?= tun
PID_FILE  ?= $(DATA_DIR)/serve.pid

## Boot the embedded sing-box with configs/config.json
run: build
	./trust-proxy -c configs/config.json

## Compile the Go backend (with $(TAGS) if set); serves dashboard from disk
build:
	go build $(if $(TAGS),-tags "$(TAGS)",) -ldflags "$(LDFLAGS)" -o trust-proxy .

## Single self-contained binary: build the dashboard then embed it (embed_ui)
build-embed: dashboard
	go build -tags "$(TAGS) embed_ui" -ldflags "$(LDFLAGS)" -o trust-proxy .

## Build embedded UI + binary, then restart the daemon.
## One sudo wraps stop+start (one password). Override MODE=manual to skip root if unused.
redeploy: build-embed
	@echo "==> restarting serve (data=$(DATA_DIR) mode=$(MODE))"
	sudo sh -c '$(CURDIR)/trust-proxy proxy stop --pid "$(PID_FILE)" 2>/dev/null || true; \
		sleep 1; \
		cd "$(CURDIR)" && ./trust-proxy serve --daemon --data "$(DATA_DIR)" -c "$(CONFIG)" --mode "$(MODE)"'
	@echo "==> done. UI http://127.0.0.1:9096/  (hard-refresh if needed)"
	@echo "    stop:  sudo $(CURDIR)/trust-proxy proxy stop --pid $(PID_FILE)"

tidy:
	go mod tidy

## Run the end-to-end proxy protocol test (self-hosted server <-> client tunnel)
e2e:
	go test $(if $(TAGS),-tags "$(TAGS)",) -run TestProxyE2E -v ./internal/proxygen/

## First-time setup: fetch the sing-box submodule
deps:
	git submodule update --init --recursive

## Build the cloned official dashboard into webui/dist
## (uses pnpm; runs codegen `generate` before build — buf generates the
##  protobuf/Connect client into src/gen, which the app imports)
webui:
	cd $(WEBUI_DIR) && corepack pnpm install --frozen-lockfile && corepack pnpm run generate && corepack pnpm run build

## Run the dashboard dev server (talks to the api service on :9095)
webui-dev:
	cd $(WEBUI_DIR) && corepack pnpm run dev

## Frontend unit tests (vitest, jsdom): pages rendered against a mocked API
dashboard-test:
	cd dashboard && corepack pnpm test

## Build the shadcn dashboard -> dashboard/dist (served at :9096, the default UI)
dashboard:
	cd dashboard && corepack pnpm install && corepack pnpm build

## Run the dashboard dev server (Vite at :3100, proxies /api -> :9096)
dashboard-dev:
	cd dashboard && corepack pnpm dev

## --- desktop shell (macOS slice) ---------------------------------------------
## The sidecar MUST be the embed_ui build: inside a .app there is no
## dashboard/dist on disk to serve the console from.
DESKTOP_TRIPLE ?= $(shell rustc -vV | sed -n 's/^host: //p')

desktop-sidecar: build-embed
	mkdir -p desktop/src-tauri/binaries
	cp trust-proxy desktop/src-tauri/binaries/trust-proxy-$(DESKTOP_TRIPLE)

## Build Trust Proxy.app (+ dmg) with the gateway bundled as a sidecar.
## Ad-hoc signs by default ("-"): without it Tauri leaves the bundle unsealed and
## even `spctl` cannot assess it ("code has no resources but signature indicates
## they must be present"). Ad-hoc is not notarization — Gatekeeper still asks the
## user once — but it makes the bundle well-formed. Set APPLE_SIGNING_IDENTITY to
## a real "Developer ID Application: …" to sign for distribution.
APPLE_SIGNING_IDENTITY ?= -

desktop: desktop-sidecar
	cd desktop && corepack pnpm install && APPLE_SIGNING_IDENTITY="$(APPLE_SIGNING_IDENTITY)" corepack pnpm build

## Run the shell against a dev build (attaches to a running gateway if there is one)
desktop-dev: desktop-sidecar
	cd desktop && corepack pnpm install && corepack pnpm dev

clean:
	rm -f trust-proxy
	rm -rf desktop/src-tauri/binaries desktop/src-tauri/target
