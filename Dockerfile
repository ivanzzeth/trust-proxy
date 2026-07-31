# trust-proxy as a container image — for Kubernetes (DaemonSet node gateway)
# and for anyone who would rather run the gateway from an image than install it.
#
# The entrypoint is `serve`, not `install`, and that is a deliberate exception to
# the one-gateway-per-machine rule rather than a shortcut around it. On bare
# metal `install` exists because nothing else supervises the process: it places a
# managed copy, registers a service, arranges start-on-boot and adopts old data.
# In Kubernetes kubelet does all four — the Pod spec *is* the service definition
# and a PVC *is* the data directory. Running `install` in here would register a
# systemd unit inside a container that has no systemd, in a filesystem that is
# discarded on restart.
#
# `serve` is hidden in the CLI and points non-privileged callers at `install`;
# that refusal is gated on paths.Privileged(), and this container runs as root
# with NET_ADMIN, so it does not fire. See docs/kubernetes.md.

# ---- dashboard -------------------------------------------------------------
# Node 22, not 20: dashboard/package.json pins pnpm 11, which imports
# node:sqlite. Same constraint the release workflow documents.
FROM node:22-bookworm-slim AS ui
WORKDIR /src
# pnpm-workspace.yaml belongs in the dependency layer with the manifest and the
# lockfile, not with the sources: pnpm 11 gates dependency build scripts and
# reads the `allowBuilds` approval from *that* file (not package.json#pnpm).
# Without it here, `pnpm install` fails with ERR_PNPM_IGNORED_BUILDS over
# esbuild — a failure the console CI job cannot reproduce, because it has the
# whole checkout and this stage deliberately does not.
COPY dashboard/package.json dashboard/pnpm-lock.yaml dashboard/pnpm-workspace.yaml dashboard/
RUN corepack enable && cd dashboard && corepack pnpm install --frozen-lockfile
COPY dashboard/ dashboard/
RUN cd dashboard && corepack pnpm build

# ---- binary ----------------------------------------------------------------
FROM golang:1.25-bookworm AS build
WORKDIR /src
# Kept in step with the Makefile's TAGS, plus embed_ui: the image ships one file
# that already contains its console, for the same reason the desktop sidecar
# does — there is no dashboard/dist to point --console at in here.
ARG TAGS="with_clash_api with_quic with_utls with_grpc with_gvisor with_wireguard with_tailscale embed_ui"
ARG VERSION=dev
ARG TARGETARCH
# go.mod `replace`s sing-box to the submodule, so it must be present before the
# module cache warms.
COPY go.mod go.sum ./
COPY third_party/ third_party/
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=ui /src/dashboard/dist dashboard/dist
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux GOARCH="${TARGETARCH:-amd64}" \
    go build -tags "$TAGS" -trimpath \
      -ldflags "-s -w -X github.com/ivanzzeth/trust-proxy/cmd.version=${VERSION}" \
      -o /out/trust-proxy .

# ---- runtime ---------------------------------------------------------------
FROM debian:12-slim
# nftables: auto_redirect is what captures *forwarded* traffic (Pod veth -> CNI
#   bridge -> forward chain), which is the entire point of the DaemonSet shape.
#   sing-tun talks netlink directly and does not shell out to `nft`, but
#   `trust-proxy doctor` reports on it and it is what you reach for when a node
#   misbehaves — an image where you cannot read the ruleset is an image you
#   cannot debug.
# iproute2: same reason (ip route / ip rule under a live tunnel).
# ca-certificates: subscription fetches and remote rule-sets are https.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables iproute2 ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/trust-proxy /usr/local/bin/trust-proxy

# The data directory. Mount a PVC here or policies, subscriptions and history
# die with the Pod; docs/kubernetes.md says so in the place people will look.
VOLUME ["/var/lib/trust-proxy"]

# 21584 proxy inbound / 21585 API + console / 21586 Clash (internal).
EXPOSE 21584 21585

ENTRYPOINT ["/usr/local/bin/trust-proxy", "serve"]
