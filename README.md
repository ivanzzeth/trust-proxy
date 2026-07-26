# trust-proxy

出入网流量控制 / 检测 / 木马外泄识别网关，以 [sing-box](https://github.com/SagerNet/sing-box) 为数据面底座。

出网流量经 trust-proxy → **默认拒绝**（黑名单追不完，只有许可制才卡死木马向任意 C2 回传）→ **检测**异常出网（威胁情报、beaconing、DGA/DNS 隧道、异常大上传=疑似外泄、JA4 指纹）→ 经订阅或自建节点出口。

一个二进制，三种角色：

| 角色 | 命令 | 说明 |
|---|---|---|
| **客户端网关** | `trust-proxy serve` | mixed 入站(:17070) + 策略 + 检测 + 控制台/API(:9096) |
| **TUN 全流量网关** | `sudo trust-proxy serve -c configs/config.tun.json` | 网络层接管**所有**流量（木马裸 socket 也逃不掉），需 root |
| **代理服务端（出口节点）** | `trust-proxy proxy gen` / `proxy run` | 自建任意协议出口节点 |

## 快速开始

依赖：Go 1.24.7+、Node 20+ / pnpm（构建控制台）。

```bash
make deps            # git submodule update --init --recursive（拉 sing-box）
make dashboard       # 构建控制台 -> dashboard/dist
make build           # 编译 -> ./trust-proxy（开发：从磁盘 serve dashboard/dist）
make build-embed     # 发布：-tags embed_ui 把 UI 嵌进二进制，单文件自带控制台
./trust-proxy serve            # 前台
./trust-proxy serve --daemon   # 后台（停止：proxy stop --pid ~/.trust-proxy/serve.pid）
```

控制台：**http://127.0.0.1:9096/**（`serve` 启动日志会打印）。

**数据目录**默认 `~/.trust-proxy`（订阅/策略/历史/`cache.db`/`clash-secret`），`--data <dir>` 覆盖。**同一数据目录勿并跑两实例**（bolt 单写锁）。

## 安全模型：Permit ⊥ Route

出网默认**拒绝**，两条正交轴永远分开：

| 轴 | 问题 | 默认 |
|---|---|---|
| **Permit** | 这个目的地能不能出网？ | 否 |
| **Route** | 已许可的流量走哪个出口？ | Final（默认 `proxy`） |
| **Deny** | 硬拒绝（优先于 Permit） | 空 |
| **Subjects** | 哪个进程/设备可出网 | 不限制 |

**铁律**：Route 永不开闸，Permit 永不选出口。第三条铁律是 **DNS 必须跟随 Route**——解析器的出网路径要和流量一致，否则国内站点会被解析到境外边缘节点再直连过去（实测 taobao 15.8s → 修复后 0.2s）。详见 [CLAUDE.md](./CLAUDE.md)。

## 桌面端（macOS）

```bash
make desktop   # -> Trust Proxy.app + .dmg
```

壳只负责开窗和生命周期，UI 就是网关 serve 的控制台；已有网关在跑则**贴附**而不再起一个。

**app 未签名**（也不打算签）：自己构建的双击即开；下载来的需放行一次 —— `xattr -dr com.apple.quarantine "/Applications/Trust Proxy.app"`，或系统设置 → 隐私与安全性 →「仍要打开」。

TUN 需要 root → 装成系统服务（launchd 拥有 daemon，关窗不掉策略）：

```bash
sudo trust-proxy service install -c ~/.trust-proxy/config.json
sudo trust-proxy service uninstall   # 逃生口
```

细节见 [docs/desktop.md](docs/desktop.md)。

## CLI / SDK

控制台能做的，命令行都能做；每个子命令都有 `--json`，`--api-addr`/`--api-token` 可指向本机或远程探针。

```
status | acl | rules | dns | mode | routing | posture | final | profile | proxies | groups
endpoints | tun | inbound | autoblock | detect | detections | quarantine | netcheck | history
node | sub | conn | proxy gen|run|stop | service install|uninstall|status
```

SDK 两层：`pkg/clash`（标准 Clash API 原语，可复用于任何 sing-box/mihomo/clash）+ `pkg/client`（本项目 `/api` 的易用封装，组合 clash）；wire 类型只在 `pkg/apitypes`。

## 端口（均绑 loopback）

| 服务 | 地址 |
|---|---|
| 代理入站 (mixed) | `127.0.0.1:17070` |
| **后端 /api + 控制台** | `127.0.0.1:9096` |
| Clash API（`pkg/clash` 消费，secret 在数据目录） | `127.0.0.1:9090` |
| 官方 sing-box dashboard（可选） | `127.0.0.1:9095` |

客户端网关默认不开 TUN、不改系统代理，与本机其它代理工具互不干扰。

## 文档

| 文档 | 内容 |
|---|---|
| [CLAUDE.md](./CLAUDE.md) | 架构、开发顺序铁律、注入分层、上游同步、**已踩的坑**、路线图 |
| [docs/console.md](docs/console.md) | 控制台各页 |
| [docs/operations.md](docs/operations.md) | 抓取/路由模式、防板砖、检测处置、多网关、TUN 与权限 |
| [docs/nodes.md](docs/nodes.md) | 订阅解析、自建出口节点、代理分组 |
| [docs/desktop.md](docs/desktop.md) | 桌面端、未签名安装、系统服务 |
| [docs/release-macos.md](docs/release-macos.md) | 签名 / 公证（决定不做，流程留档） |
| [docs/egress-enforcement-risks.md](docs/egress-enforcement-risks.md) | 出口**强制**类改造为何暂缓 + 7 条防板砖验收标准 |
| [docs/TODO.md](docs/TODO.md) | 待办 |

## 许可证与归属

本项目以 **GPLv3** 授权（见 [LICENSE](./LICENSE)），因为它链接/内嵌了 GPLv3 的上游代码。分发源码或二进制须遵守 GPLv3（保留声明、随附对应源码）。

- [sing-box](https://github.com/SagerNet/sing-box) — 数据面（子模块），**GPLv3**（+ 命名附加条款：衍生品不得使用其名称做宣传）
- [shadcn/ui](https://ui.shadcn.com) + [Radix UI](https://www.radix-ui.com) — 控制台组件，MIT
- [sing-box-dashboard](https://github.com/SagerNet/sing-box-dashboard) — 可选官方监控面板（`webui/`），GPLv3
