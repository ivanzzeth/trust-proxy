SING_BOX_DIR := third_party/sing-box
WEBUI_DIR    := webui

# Build tags. with_clash_api exposes the Clash REST/WS API our own backend
# consumes (connections / traffic / logs / DELETE connection). Add more as
# features come online, e.g.:
#   with_quic   -> Hysteria2 / TUIC / QUIC sniffing
#   with_utls   -> uTLS fingerprints
TAGS ?= with_clash_api

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

clean:
	rm -f trust-proxy
