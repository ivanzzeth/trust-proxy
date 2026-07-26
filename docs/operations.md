# 运行时：配置位置 / 抓取模式 / 路由模式 / 防板砖 / 检测处置 / 多网关

## 配置在哪（只有一处）

`<data>/config.json`，默认即 `~/.trust-proxy/config.json`，**首次启动自动种下**（来源：编译进二进制的 `configs/config.json`）。之后那份文件就是用户的，升级**绝不覆盖**。

`-c` 只作显式覆盖（`configs/config.tun.json`、线上钉死的某份文件）。

为什么要收进数据目录：`-c` 原先默认 `configs/config.json`——一个**仓库相对路径**，只在 checkout 里跑才有意义。于是桌面端（没有仓库、cwd 也不在仓库）只能另挑位置，还各自实现了一遍「首启种默认配置」，结果同一台机器上 CLI daemon 与桌面 app 可能读不同配置、连抓取模式都不一样。现在配置和它所属的数据在一起，三条路径（CLI / 桌面壳 / 系统服务）读同一个文件。

**从旧版升级**：若当前目录存在老路径 `configs/config.json`，首启会**以它为种子**（打印 `seeded … from configs/config.json`），你在仓库里的改动跟着迁移，不会被内置默认悄悄取代。

## 抓取模式（运行时可切换）

`manual`（客户端指 `127.0.0.1:21584`）/ `system`（设为系统代理）/ `tun`（网络层全接管，需 root）。

控制台顶栏或 `POST /api/mode` 热切换，`serve --mode` 指定初始模式。TUN 无 root 会**自动回滚**到上个模式、网关不掉线（控制台会弹平台相关的提权引导，而不是抛 `operation not permitted`）。

## 路由模式 Rule ↔ Global（`/api/clash-mode`）

- `Rule` = 默认拒绝（安全默认值）。
- `Global` = **默认拒绝关闭**，未许可流量改走 `proxy` 组出网——但**安全 floor 仍生效**（Deny 名单 / 威胁情报 / 进程·设备闸照样拦）。

**热切换、不重建数据面**（Clash `PATCH /configs`）；只放行 Rule/Global，**拒绝 Direct**（否则等于全直连泄漏）；选择经 `cache_file` 持久化。Global 时控制台全局显琥珀警告横幅。

## 姿势 Strict ↔ Split

`Strict` = 出网默认拒绝；`Split` = 默认允许但 L4 路由照旧。两个姿势各有独立的策略槽，切换是整份替换——所以**网关自行封禁的目的地存在独立的隔离区**（`internal/quarantine`），不会随姿势切换消失。

## 远程安全（防板砖）

远程机开 TUN / 系统代理时：

1. **管理端口豁免** —— SSH + 本机 API 端口的响应始终绕过默认拒绝（注入在最顶层，`--management-ports`，API 口自动加），不会切断你的连接。
2. **死亡开关** —— 控制台切 TUN/系统代理会武装 60s 定时器，**你不点「保持」确认就自动回退**，真锁死了机器自己救回来（`/api/mode` 的 `guard_seconds` + `/api/mode/confirm`）。

更激进的出口强制手段（pf kill switch、收窄 LAN 旁路、剥 ECH、拦 DoH）**故意不做**，理由与真要做时的 7 条验收标准见 [`egress-enforcement-risks.md`](egress-enforcement-risks.md)。

## 检测与处置

- **威胁情报 feed**：默认拉 abuse.ch Feodo C2 IP 黑名单（CC0），后台定时刷新替换。`--threat-feeds`（逗号多源）/ `--threat-refresh` / `--no-threat-feed`。
- **自动处置**：`--auto-block`（默认开）命中威胁的连接直接断；控制台可切换。**启发式只告警不封禁**；且处置会等 Permit 索引就绪（`require_warm_permit`），否则规则集还没拉下来时会把你其实批准过的目的地封掉。
- **阈值全部可配**：`/api/detection-config`、`trust-proxy detect get|set`、Detection 页三处等价，改完直接进引擎（无需重建）。
- **事件持久化**：审计事件定时 + 退出快照，重启恢复；每条完成连接进 `history.jsonl`（lumberjack 轮转/保留/gzip）。

## 多网关（探针 + 大脑）

任一 `serve` 即探针。暴露给远程时：

```bash
trust-proxy serve --api-addr 0.0.0.0:21585 --api-token <secret>   # /api/* 需 bearer
```

在其中一台打开控制台（大脑）→ Gateways 页注册其余网关 → 顶栏切换视图；大脑反代 `/api/nodes/{id}/*` 到各探针并注入各自 token（浏览器仍单 origin、不碰 token）。

## TUN 全流量网关

```bash
sudo ./trust-proxy serve -c configs/config.tun.json
```

`tun` 入站 + `auto_route` 网络层接管全部出入网流量（木马的裸 socket 也逃不掉）。需 **root**，与其它 TUN 工具（Surge 增强模式等）互斥 → 用于专用网关机 / 软路由。检测与策略逻辑不变（同一 route）。

### 权限：sudo vs 非 sudo（建议默认 sudo）

| 启动方式 | manual / system | **TUN**（含运行时切到 TUN） | 适用 |
|---|---|---|---|
| **`sudo` 启动（推荐）** | ✅ | ✅ | 网关机 / 想随时切 TUN |
| 非 sudo | ✅ | ❌ 建 TUN 网卡报 `operation not permitted` | 只用代理模式 |

- **Linux 想以非 root 常驻**：`sudo setcap 'cap_net_admin,cap_net_raw+ep' ./trust-proxy`（每次重编译要重授）。
- **容器**：Docker 加 `--cap-add=NET_ADMIN --device=/dev/net/tun`；Proxmox 非特权 LXC 需宿主放行 `/dev/net/tun`。
- **macOS 桌面端**：别用 sudo 跑 GUI，装成系统服务（见 [`desktop.md`](desktop.md)）。
- **数据属主**：sudo 与非 sudo 混跑会让 `~/.trust-proxy` 下文件属主混乱（`cache.db` 锁失败）——**固定一种方式**。同一数据目录**勿并跑两实例**（bolt 单写锁）。
