#!/usr/bin/env bash
# 生成 trust-proxy 生产配置骨架：拷模板、生成 API_TOKEN、列出还要填什么。
# 幂等：目标已存在则拒绝覆盖。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_NAME="${1:-prod}"
DEST="$ROOT/deploy/env/$ENV_NAME"
TPL="$ROOT/deploy/env/prod.example/config.env"

[ -f "$TPL" ] || { echo "找不到模板 $TPL" >&2; exit 1; }
if [ -e "$DEST/config.env" ]; then
    echo "已存在：$DEST/config.env" >&2
    echo "不覆盖 —— 要重新生成请先自己移走。" >&2
    exit 1
fi

command -v openssl >/dev/null || { echo "需要 openssl 生成密钥" >&2; exit 1; }

mkdir -p "$DEST"
cp "$TPL" "$DEST/config.env"

token="$(openssl rand -hex 32)"
perl -pi -e "s/^API_TOKEN=\$/API_TOKEN=${token}/" "$DEST/config.env"

chmod 700 "$DEST"
chmod 600 "$DEST/config.env"

printf '\n\033[1;36m==>\033[0m 已生成 %s\n\n' "$DEST/config.env"
echo "API_TOKEN 已生成。"
echo
echo "还需要你填："
grep -nE '^[A-Z_]+=$' "$DEST/config.env" | sed 's/^/  /' \
    | grep -vE 'REGISTRY_PASSWORD|API_TOKEN' || true
echo
echo "另外："
echo "  cp <admin-kubeconfig> $DEST/kubeconfig.yaml && chmod 600 $DEST/kubeconfig.yaml"
echo "  （可与 lingxiao/ai-router 共用同一份 ACK kubeconfig）"
echo
echo "冒烟："
echo "  make release ONLY=preflight"
echo
echo "⛔ 生产必须 GATEWAY_MODE=manual（默认已是）。不要改成 tun。"
