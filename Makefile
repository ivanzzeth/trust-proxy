SING_BOX_DIR := third_party/sing-box
WEBUI_DIR    := webui

# Build tags:
#   with_clash_api -> Clash REST/WS API our backend consumes (pkg/clash)
#   with_quic      -> Hysteria2 / TUIC / QUIC (common in real subscriptions)
#   with_utls      -> uTLS fingerprints (vless reality/tls fp)
#   with_grpc      -> full gRPC transport (there is a lite fallback without it)
TAGS ?= with_clash_api with_quic with_utls with_grpc with_gvisor

.PHONY: run build tidy webui webui-dev dashboard dashboard-dev deps clean e2e

## Boot the embedded sing-box with configs/config.json
run: build
	./trust-proxy -c configs/config.json

## Compile the Go backend (with $(TAGS) if set)
build:
	go build $(if $(TAGS),-tags "$(TAGS)",) -o trust-proxy .

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

## Build the shadcn dashboard -> dashboard/dist (served at :9096, the default UI)
dashboard:
	cd dashboard && corepack pnpm install && corepack pnpm build

## Run the dashboard dev server (Vite at :3100, proxies /api -> :9096)
dashboard-dev:
	cd dashboard && corepack pnpm dev

clean:
	rm -f trust-proxy
