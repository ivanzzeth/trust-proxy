SING_BOX_DIR := third_party/sing-box
WEBUI_DIR    := webui

# Build tags: milestone 0 needs none (the api service is compiled unconditionally).
# Add more as features come online, e.g.:
#   with_clash_api  -> also expose the Clash REST/WS API (for zashboard/metacubexd)
#   with_quic       -> Hysteria2 / TUIC / QUIC sniffing
#   with_utls       -> uTLS fingerprints
TAGS ?=

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
