#!/usr/bin/env bash
# 生产发布入口 —— 与 ai-sandbox / ai-router 同一个模型：本地构建 → 推 ACR → helm upgrade。
#
# Usage:
#   ./scripts/release.sh --mode manual --tag v0.13.0
#                        [--only preflight,build,push,secrets,adopt,deploy,verify,tag]
#                        [--skip push]
#                        [--env-dir deploy/env/prod]
#                        [--dry-run]
#
#   make release TAG=v0.13.0
#   make release ONLY=preflight
#   make release SKIP=build,push TAG=v0.13.0   # 镜像已在仓库，只升 helm（回滚同此）
#
# 配置一律来自 --env-dir（默认 deploy/env/prod）：kubeconfig.yaml + config.env。
#
# ⛔ ACK / AI 网关出口默认必须 mode=manual（workload 用 HTTPS_PROXY / proxy_url 接入）。
#    mode=tun 会接管节点转发，可能拖垮集群其他网络；只有显式 ALLOW_TUN_MODE=1 才放行。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
CHART="$ROOT/deploy/helm/trust-proxy"

# ⚠️ 清掉 GH_TOKEN：git 的 credential.helper 是 `gh auth git-credential`，而 gh 会【优先】
# 用 GH_TOKEN 环境变量。若 shell profile 里留着过期 token，tag 阶段的 git push 会挂。
unset GH_TOKEN

MODE=manual
TAG=""
ONLY=""
SKIP=""
ENV_DIR="$ROOT/deploy/env/prod"
DRY_RUN=0

usage() {
    sed -n '/^# Usage:/,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'
    exit "${1:-0}"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --mode) MODE="${2:-}"; shift 2 ;;
        --tag) TAG="${2:-}"; shift 2 ;;
        --only) ONLY="${2:-}"; shift 2 ;;
        --skip) SKIP="${2:-}"; shift 2 ;;
        --env-dir) ENV_DIR="${2:-}"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; usage 2 ;;
    esac
done

[[ "$ENV_DIR" = /* ]] || ENV_DIR="$ROOT/$ENV_DIR"

die() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
info() { printf '  · %s\n' "$*"; }
warn() { printf '  \033[1;33m⚠\033[0m %s\n' "$*" >&2; }

case "$MODE" in
    manual) ;;
    ci|argocd) die "--mode ${MODE} 尚未实现。此刻只支持 --mode manual。" ;;
    *) die "--mode 必须是 manual|ci|argocd(got '${MODE}')" ;;
esac

ALL_STAGES="preflight build push secrets adopt deploy verify tag"

stage_enabled() {
    case ",${SKIP}," in *",$1,"*) return 1 ;; esac
    [ -z "${ONLY}" ] && return 0
    case ",${ONLY}," in *",$1,"*) return 0 ;; *) return 1 ;; esac
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "缺少命令:$1 — $2"
}

placeholder() { case "$1" in ""|*example.com*|*CHANGE_ME*|*xxxxxxxx*|*your-*) return 0 ;; esac; return 1; }

CONFIG_LOADED=0
load_config() {
    [ "$CONFIG_LOADED" = 1 ] && return 0
    local cfg="$ENV_DIR/config.env"
    local kc="$ENV_DIR/kubeconfig.yaml"
    [ -d "$ENV_DIR" ] || die "环境目录不存在:$ENV_DIR
      make release-init"
    [ -f "$kc" ] || die "缺少 $kc — 把目标集群的 admin kubeconfig 放到这里"
    [ -f "$cfg" ] || die "缺少 $cfg
      make release-init 然后填实值"
    set -a
    # shellcheck disable=SC1090
    . <(grep -vE '^\s*(#|$)' "$cfg")
    set +a
    export KUBECONFIG="$kc"
    chmod 600 "$kc" 2>/dev/null || true
    PUSH_REPOSITORY="${PUSH_REPOSITORY:-${IMAGE_REPOSITORY:-}}"
    TAG="${TAG:-${IMAGE_TAG:-}}"
    NAMESPACE="${NAMESPACE:-trust-proxy}"
    RELEASE="${RELEASE:-trust-proxy}"
    IMAGE_PULL_SECRET_NAME="${IMAGE_PULL_SECRET_NAME:-trust-proxy-registry}"
    API_SECRET_NAME="${API_SECRET_NAME:-trust-proxy}"
    API_TOKEN_KEY="${API_TOKEN_KEY:-api-token}"
    # 网关捕获模式：生产默认 manual。config.env 的 GATEWAY_MODE 可覆盖，但仍受 ALLOW_TUN_MODE 门禁。
    GATEWAY_MODE="${GATEWAY_MODE:-manual}"
    if [ "${DOCKER_SUDO:-0}" = "1" ]; then DOCKER=(sudo docker); else DOCKER=(docker); fi
    CONFIG_LOADED=1
}

docker_cmd() { "${DOCKER[@]}" "$@"; }

RELEASE_LEDGER_DIR="$ROOT/.release/digests"

release_digest_file() {
    printf '%s/%s.env' "$RELEASE_LEDGER_DIR" "$1"
}

known_release_tags() {
    local f base
    for f in "$RELEASE_LEDGER_DIR"/*.env; do
        [ -e "$f" ] || continue
        base="${f##*/}"
        printf '%s\n' "${base%.env}"
    done
    git -C "$ROOT" tag --merged HEAD --list 'v*' 2>/dev/null || true
}

suggest_next_tag() {
    local max
    max=$(known_release_tags | sort -V | uniq | tail -1)
    [ -n "$max" ] || { echo "v0.13.0"; return; }
    echo "$max" | awk -F. '{ sub(/^v/,"",$1); printf "v%s.%s.%d\n", $1, $2, $3+1 }'
}

version_lte() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$1" ]; }

assert_fresh_release_tag() {
    [ -n "$TAG" ] || die "需要 --tag 或 config.env 里的 IMAGE_TAG"
    case "$TAG" in v*) ;; *) die "TAG 要以 v 开头（例 v0.13.0），拿到的是 $TAG" ;; esac
    if [ "${FORCE_RELEASE_TAG:-0}" = "1" ]; then
        warn "FORCE_RELEASE_TAG=1 —— 跳过「TAG 未用过」检查"
        return 0
    fi
    local next digest_file
    next=$(suggest_next_tag)
    digest_file=$(release_digest_file "$TAG")
    [ ! -f "$digest_file" ] || die \
"TAG=${TAG} 已发过（本机 digest 账本）。下一号建议：${next}
      回滚：make release SKIP=build,push TAG=${TAG}"
    ! git -C "$ROOT" rev-parse -q --verify "refs/tags/${TAG}" >/dev/null 2>&1 || die \
"TAG=${TAG} 本地已有 git tag。建议 ${next}"
    if git -C "$ROOT" remote get-url origin >/dev/null 2>&1; then
        ! git -C "$ROOT" ls-remote --exit-code --tags origin "refs/tags/${TAG}" >/dev/null 2>&1 || die \
"TAG=${TAG} 远端已有 git tag。建议 ${next}"
    fi
    local max; max=$(known_release_tags | sort -V | uniq | tail -1)
    if [ -n "$max" ] && version_lte "$TAG" "$max"; then
        die "TAG=${TAG} 不新于已用过的最大号 ${max}。建议 ${next}"
    fi
}

assert_gateway_mode_safe() {
    case "$GATEWAY_MODE" in
        manual|system) ;;
        tun)
            if [ "${ALLOW_TUN_MODE:-0}" = "1" ]; then
                warn "ALLOW_TUN_MODE=1 —— 允许 mode=tun（会接管节点转发；确认这是你要的）"
            else
                die "GATEWAY_MODE=tun 会接管节点转发，可能拖垮 ACK 其他网络。
      AI 网关出口请用 mode=manual（workload 显式 HTTPS_PROXY / proxy_url）。
      若你真要 TUN，显式设 ALLOW_TUN_MODE=1。"
            fi
            ;;
        *) die "GATEWAY_MODE 必须是 manual|system|tun，拿到的是 ${GATEWAY_MODE}" ;;
    esac
}

stage_preflight() {
    log "stage preflight — 工具 · 配置 · 集群可达 · 拒打错集群 · 拒 TUN"
    need kubectl "与目标集群次版本匹配的 kubectl"
    need helm "helm 3"
    need jq "解析节点标签"
    if stage_enabled build || stage_enabled push; then
        need docker "build/push 阶段需要 Docker"
    fi
    load_config
    assert_gateway_mode_safe

    local ctx
    ctx=$(kubectl config current-context 2>/dev/null || true)
    [ -n "$ctx" ] || die "kubeconfig 没有 current-context:$KUBECONFIG"
    case "$ctx" in
        *k3d*|*kind*|*minikube*|*local*|*docker-desktop*)
            die "当前 context=$ctx 看起来是本地集群 —— 拒绝生产发布。
      检查 $ENV_DIR/kubeconfig.yaml。"
            ;;
    esac
    kubectl get --raw=/readyz >/dev/null 2>&1 \
        || kubectl cluster-info >/dev/null 2>&1 \
        || die "kubectl 连不上集群(context=$ctx)"

    local zone
    zone=$(kubectl get nodes -o json \
        | jq -r '[.items[].metadata.labels["topology.kubernetes.io/zone"] // empty] | unique | join(",")')
    info "context=$ctx  namespace=$NAMESPACE release=$RELEASE"
    info "zone(s)=$zone gateway_mode=$GATEWAY_MODE"
    if [ -n "${EXPECT_ZONE:-}" ]; then
        case "$zone" in
            *"$EXPECT_ZONE"*) info "确认:期望集群($EXPECT_ZONE)" ;;
            *) printf 'WARN: 节点 zone=%s —— 预期含 %s。若故意打别的集群请自担。\n' "$zone" "$EXPECT_ZONE" >&2 ;;
        esac
    fi

    if stage_enabled build || stage_enabled push || stage_enabled deploy; then
        [ -n "$TAG" ] || die "需要 --tag 或 config.env 里的 IMAGE_TAG"
        [ -n "${IMAGE_REPOSITORY:-}" ] || die "config.env 缺 IMAGE_REPOSITORY"
        ! placeholder "$IMAGE_REPOSITORY" || die "IMAGE_REPOSITORY 仍是占位符($IMAGE_REPOSITORY)"
    fi
    if stage_enabled build || stage_enabled push; then
        assert_fresh_release_tag
        # Dockerfile 依赖 sing-box / sing-tun 子模块。
        [ -f "$ROOT/third_party/sing-box/go.mod" ] || die "缺 third_party/sing-box —— git submodule update --init --recursive"
        [ -f "$ROOT/third_party/sing-tun/go.mod" ] || die "缺 third_party/sing-tun —— git submodule update --init --recursive"
    fi
    if stage_enabled secrets || stage_enabled deploy; then
        [ -n "${API_TOKEN:-}" ] || die "API_TOKEN 未填（make release-init 会生成）"
    fi
    info "MODE=$MODE TAG=${TAG:-—} ONLY=${ONLY:-all} SKIP=${SKIP:-—}"
    info "env-dir=$ENV_DIR image=${IMAGE_REPOSITORY:-—}"
}

stage_build() {
    load_config
    log "stage build — 构建 ${PUSH_REPOSITORY}:${TAG}"
    [ -n "$TAG" ] || die "build 需要 --tag"
    assert_fresh_release_tag
    [ -n "${PUSH_REPOSITORY:-}" ] || die "build 需要 IMAGE_REPOSITORY"

    # ACR 个人版对 buildx 默认 attestation manifest list 不友好。
    local build_flags=(--platform "${TARGET_PLATFORM:-linux/amd64}" --provenance=false --sbom=false --load)

    if [ "$DRY_RUN" -eq 1 ]; then
        info "(dry-run) docker build ${PUSH_REPOSITORY}:${TAG}"
        return 0
    fi

    DOCKER_BUILDKIT=1 docker_cmd build "${build_flags[@]}" \
        --build-arg "VERSION=${TAG}" \
        -f "$ROOT/Dockerfile" \
        -t "${PUSH_REPOSITORY}:${TAG}" "$ROOT"
    info "built ${PUSH_REPOSITORY}:${TAG}"
}

registry_login() {
    [ -n "${REGISTRY_HOST:-}" ] || return 0
    [ -n "${REGISTRY_USER:-}" ] || { info "REGISTRY_USER 空 —— 假设已 docker login"; return 0; }
    if [ -n "${REGISTRY_PASSWORD:-}" ]; then
        printf '%s' "$REGISTRY_PASSWORD" \
            | docker_cmd login --username "$REGISTRY_USER" --password-stdin "$REGISTRY_HOST" >/dev/null
        info "logged in ${REGISTRY_HOST}"
    fi
}

stage_push() {
    load_config
    log "stage push — 推送 ${PUSH_REPOSITORY}:${TAG}"
    [ -n "$TAG" ] || die "push 需要 --tag"

    if [ "$DRY_RUN" -eq 1 ]; then
        info "(dry-run) docker push + 记 digest"
        return 0
    fi
    registry_login
    docker_cmd push "${PUSH_REPOSITORY}:${TAG}"

    local digest
    digest=$(docker_cmd buildx imagetools inspect "${PUSH_REPOSITORY}:${TAG}" \
        | awk '/^Digest:/ {print $2; exit}')
    [ -n "$digest" ] || die "推上去了却读不到 digest —— 不敢往下走"

    local out
    out=$(release_digest_file "$TAG")
    mkdir -p "$RELEASE_LEDGER_DIR"
    cat > "$out" <<EOF
IMAGE_DIGEST=${digest}
EOF
    info "pushed ${digest}"
}

resolve_release_digests() {
    local file
    file=$(release_digest_file "$TAG")
    if [ -f "$file" ]; then
        # shellcheck disable=SC1090
        . "$file"
    fi
    # ⚠️ `|| true` 不能省：镜像不存在时 imagetools 非零退出，叠加 pipefail 会静默带走脚本。
    if [ -z "${IMAGE_DIGEST:-}" ]; then
        IMAGE_DIGEST=$(docker_cmd buildx imagetools inspect "${PUSH_REPOSITORY}:${TAG}" 2>/dev/null \
            | awk '/^Digest:/ {print $2; exit}' || true)
    fi
    [ -n "${IMAGE_DIGEST:-}" ] || die "缺 IMAGE_DIGEST —— 先 ONLY=push，或确认仓库有 ${PUSH_REPOSITORY}:${TAG}"
    info "deploy digest=${IMAGE_DIGEST}"
}

put_secret() {
    local name="$1"; shift
    if [ "$DRY_RUN" -eq 1 ]; then info "(dry-run) secret/$name"; return 0; fi
    kubectl -n "$NAMESPACE" create secret generic "$name" "$@" \
        --dry-run=client -o yaml | kubectl -n "$NAMESPACE" apply -f - >/dev/null
    info "secret/$name"
}

stage_secrets() {
    load_config
    log "stage secrets — API token + 镜像拉取凭据"
    assert_gateway_mode_safe
    if [ "$DRY_RUN" -eq 0 ]; then
        kubectl create namespace "$NAMESPACE" --dry-run=client -o yaml \
            | kubectl apply -f - >/dev/null
    fi

    put_secret "$API_SECRET_NAME" --from-literal="${API_TOKEN_KEY}=${API_TOKEN}"

    if [ -z "${REGISTRY_PASSWORD:-}" ]; then
        info "REGISTRY_PASSWORD 为空 —— 跳过 pull secret（假定集群已有可用凭据）"
        return 0
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        info "(dry-run) docker-registry/$IMAGE_PULL_SECRET_NAME"
        return 0
    fi
    kubectl -n "$NAMESPACE" create secret docker-registry "$IMAGE_PULL_SECRET_NAME" \
        --docker-server="$REGISTRY_HOST" \
        --docker-username="$REGISTRY_USER" \
        --docker-password="$REGISTRY_PASSWORD" \
        --dry-run=client -o yaml | kubectl -n "$NAMESPACE" apply -f - >/dev/null
    info "secret/$IMAGE_PULL_SECRET_NAME"
}

# stage_adopt：让 helm 接管既有资源（一次性迁移；不改 spec）。形状照抄 ai-sandbox。
stage_adopt() {
    load_config
    log "stage adopt — 让 helm 接管既有资源（一次性迁移；不改 spec）"
    if [ "$DRY_RUN" -eq 1 ]; then
        info "(dry-run) 给 chart 渲染出的每个既有对象打 helm 所有权标记"
        return 0
    fi

    local rendered
    rendered=$(helm template "$RELEASE" "$CHART" \
        --namespace "$NAMESPACE" --values "$CHART/values-prod.yaml" 2>/dev/null) \
        || die "helm template 失败，无法确定要接管哪些资源"

    local n=0
    while IFS=$'\t' read -r kind name ns; do
        [ -n "$kind" ] && [ -n "$name" ] || continue
        local args=(--namespace "${ns:-$NAMESPACE}")
        case "$kind" in Namespace|ClusterRole|ClusterRoleBinding) args=() ;; esac
        kubectl "${args[@]}" get "$kind" "$name" >/dev/null 2>&1 || continue
        kubectl "${args[@]}" annotate --overwrite "$kind" "$name" \
            "meta.helm.sh/release-name=${RELEASE}" \
            "meta.helm.sh/release-namespace=${NAMESPACE}" >/dev/null
        kubectl "${args[@]}" label --overwrite "$kind" "$name" \
            "app.kubernetes.io/managed-by=Helm" >/dev/null
        info "adopted ${kind}/${name}${ns:+ @$ns}"
        n=$((n + 1))
    done < <(printf '%s\n' "$rendered" | python3 -c '
import sys, yaml
for doc in yaml.safe_load_all(sys.stdin):
    if not doc:
        continue
    md = doc.get("metadata") or {}
    print("\t".join([doc.get("kind", ""), md.get("name", ""), md.get("namespace", "")]))
')
    info "共接管 ${n} 个既有对象"
}

stage_deploy() {
    load_config
    log "stage deploy — helm upgrade --install (${RELEASE}/${NAMESPACE})"
    [ -n "$TAG" ] || die "deploy 需要 --tag"
    [ -n "${IMAGE_REPOSITORY:-}" ] || die "deploy 需要 IMAGE_REPOSITORY"
    assert_gateway_mode_safe

    if [ "$DRY_RUN" -eq 1 ]; then
        IMAGE_DIGEST="sha256:$(printf '0%.0s' $(seq 64))"
    else
        resolve_release_digests
    fi

    local sets=(
        --set "image.repository=${IMAGE_REPOSITORY}"
        --set "image.tag=${TAG}"
        --set "image.digest=${IMAGE_DIGEST}"
        --set "image.pullPolicy=IfNotPresent"
        --set "mode=${GATEWAY_MODE}"
        --set "posture=${GATEWAY_POSTURE:-split}"
        --set "autoBlock=${GATEWAY_AUTO_BLOCK:-false}"
        --set "api.existingSecret=${API_SECRET_NAME}"
        --set "api.tokenKey=${API_TOKEN_KEY}"
    )
    if [ -n "${REGISTRY_USER:-}" ] || [ -n "${FORCE_PULL_SECRET:-}" ]; then
        sets+=(--set "image.pullSecrets[0].name=${IMAGE_PULL_SECRET_NAME}")
    elif [ -n "${EXISTING_PULL_SECRET:-}" ]; then
        # 现网曾用 Specula 拉镜像：可在 config.env 里写 EXISTING_PULL_SECRET=specula-pull
        sets+=(--set "image.pullSecrets[0].name=${EXISTING_PULL_SECRET}")
    fi
    if [ "${PREFLIGHT_ENABLED:-}" = "0" ] || [ "${PREFLIGHT_ENABLED:-}" = "false" ]; then
        sets+=(--set "preflight.enabled=false")
    fi

    if [ "$DRY_RUN" -eq 1 ]; then
        info "(dry-run) helm upgrade --install $RELEASE $CHART ${sets[*]}"
        helm upgrade --install "$RELEASE" "$CHART" \
            --namespace "$NAMESPACE" --create-namespace \
            --values "$CHART/values-prod.yaml" "${sets[@]}" --dry-run >/dev/null \
            || die "helm 模板渲染失败(dry-run)"
        info "(dry-run) helm 模板渲染通过"
        return 0
    fi

    helm upgrade --install "$RELEASE" "$CHART" \
        --namespace "$NAMESPACE" --create-namespace \
        --values "$CHART/values-prod.yaml" \
        --atomic --wait --timeout "${HELM_TIMEOUT:-10m}" \
        "${sets[@]}"
    info "helm release ${RELEASE} @ ${TAG} mode=${GATEWAY_MODE}"
}

stage_verify() {
    log "stage verify — DaemonSet rollout · digest 核对 · /api/health"
    load_config
    if [ "$DRY_RUN" -eq 1 ]; then
        info "(dry-run) rollout status + digest 核对 + health"
        return 0
    fi
    resolve_release_digests

    kubectl -n "$NAMESPACE" rollout status "daemonset/${RELEASE}" --timeout=300s

    # 事实核对：运行中的 pod 用的 digest 必须等于本次发的。
    local running
    running=$(kubectl -n "$NAMESPACE" get pods -l "app.kubernetes.io/instance=${RELEASE}" \
        -o jsonpath='{range .items[*]}{.status.containerStatuses[?(@.name=="gateway")].imageID}{"\n"}{end}' \
        2>/dev/null | grep -v '^$' | sort -u || true)
    [ -n "$running" ] || die "取不到运行中 gateway 的 imageID —— 无法证明发布生效"
    if ! printf '%s' "$running" | grep -q "${IMAGE_DIGEST#sha256:}"; then
        die "生产跑的不是本次发布的镜像。
      期望 digest: ${IMAGE_DIGEST}
      实际 imageID:
$(printf '%s\n' "$running" | sed 's/^/        /')"
    fi
    info "digest 核对通过:生产在跑 ${IMAGE_DIGEST}"

    # 确认没有误开 TUN
    local mode_args
    mode_args=$(kubectl -n "$NAMESPACE" get ds "$RELEASE" \
        -o jsonpath='{.spec.template.spec.containers[?(@.name=="gateway")].args}' 2>/dev/null || true)
    case "$mode_args" in
        *--mode=tun*)
            if [ "${ALLOW_TUN_MODE:-0}" != "1" ]; then
                die "DaemonSet 参数里出现 --mode=tun —— 拒绝验收"
            fi
            ;;
        *--mode="${GATEWAY_MODE}"*|*--mode=${GATEWAY_MODE}*) info "mode=${GATEWAY_MODE} 已写入 DaemonSet" ;;
        *) warn "未能从 args 解析 mode（继续探活）" ;;
    esac

    local pod
    pod=$(kubectl -n "$NAMESPACE" get pods -l "app.kubernetes.io/instance=${RELEASE}" \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
    [ -n "$pod" ] || die "没有可探活的 Pod"
    kubectl -n "$NAMESPACE" exec "$pod" -c gateway -- \
        wget -qO- --timeout=5 "http://127.0.0.1:21585/api/health" >/dev/null \
        || die "gateway /api/health 失败"
    info "health OK · pod=$pod"
    kubectl -n "$NAMESPACE" get ds,pods
}

stage_tag() {
    log "stage tag — 打 git tag ${TAG}（默认不 push；需要时自行 git push --tags）"
    [ -n "$TAG" ] || die "tag 阶段需要 --tag"
    if [ "$DRY_RUN" -eq 1 ]; then
        info "(dry-run) git tag $TAG"
        return 0
    fi
    if git -C "$ROOT" rev-parse -q --verify "refs/tags/${TAG}" >/dev/null 2>&1; then
        info "本地已有 tag $TAG"
        return 0
    fi
    git -C "$ROOT" tag -a "$TAG" -m "release ${TAG}"
    info "created tag $TAG"
}

for s in $ALL_STAGES; do
    if stage_enabled "$s"; then
        "stage_$s"
    else
        printf '  (skip %s)\n' "$s"
    fi
done

log "release 完成 TAG=${TAG:-—} DRY_RUN=$DRY_RUN mode=${GATEWAY_MODE:-—}"
