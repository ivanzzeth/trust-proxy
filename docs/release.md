# 生产发布（ACK）

与 `ai-sandbox` / `ai-router` 同一模型：本地构建 → 推镜像仓库 → `helm upgrade` → 核对 digest。

```bash
make release-init          # 生成 deploy/env/prod/（不入库）
# 填 IMAGE_REPOSITORY / REGISTRY_* ，拷入 kubeconfig.yaml
make release ONLY=preflight
make release TAG=v0.13.0
```

## 硬约束

- **`GATEWAY_MODE=manual`（默认）**：只起 mixed inbound；AI 网关供应源用 `proxy_url` / `HTTPS_PROXY` 显式接入。国内直连集群内地址。
- **禁止 `mode=tun`**：会接管节点转发，可能拖垮 ACK 其他网络。release 脚本门禁拒绝；确需时显式 `ALLOW_TUN_MODE=1`。
- **digest 部署**：`helm` 用 `repo@sha256:…`，verify 核对运行中 Pod 的 imageID。

## 与桌面发版的分界

| 目标 | 做什么 |
|---|---|
| `make release` | ACK Helm 发布（本文件） |
| `make desktop-release VERSION=…` | 桌面壳三处版本号对齐（`scripts/cut-desktop-release.sh`） |

## 现网

namespace / release：`trust-proxy`。节点需 `trust-proxy.io/gateway=true`。与 Lingxiao 同一 ACK（`EXPECT_ZONE=cn-chengdu-b`）。
