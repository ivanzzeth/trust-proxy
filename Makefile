SING_BOX_DIR := third_party/sing-box
WEBUI_DIR    := webui

# Build tags:
#   with_clash_api -> Clash REST/WS API our backend consumes (pkg/clash)
#   with_quic      -> Hysteria2 / TUIC / QUIC (common in real subscriptions)
#   with_utls      -> uTLS fingerprints (vless reality/tls fp)
#   with_grpc      -> full gRPC transport (there is a lite fallback without it)
TAGS ?= with_clash_api with_quic with_utls with_grpc

.PHONY: run build tidy webui webui-dev deps clean

## Boot the embedded sing-box with configs/config.json
run: build
	./trust-proxy -c configs/config.json

## Compile the Go backend (with $(TAGS) if set)
build:
	go build $(if $(TAGS),-tags "$(TAGS)",) -o trust-proxy .

tidy:
	go mod tidy

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

## Build our own React console -> console/dist (served by the backend at :9096)
console:
	cd console && npm install && npm run build

## Run the console dev server (Vite, proxies /api to :9096)
console-dev:
	cd console && npm run dev

clean:
	rm -f trust-proxy
