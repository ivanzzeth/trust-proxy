# 运行时：配置位置 / 账号权限 / 抓取模式 / 路由模式 / 防板砖 / 检测处置 / 多网关

## 配置在哪（只有一处）

`<data>/config.json`，默认即 `~/.trust-proxy/config.json`，**首次启动自动种下**（来源：编译进二进制的 `configs/config.json`）。之后那份文件就是用户的，升级**绝不覆盖**。

`-c` 只作显式覆盖（`configs/config.tun.json`、线上钉死的某份文件）。

为什么要收进数据目录：`-c` 原先默认 `configs/config.json`——一个**仓库相对路径**，只在 checkout 里跑才有意义。于是桌面端（没有仓库、cwd 也不在仓库）只能另挑位置，还各自实现了一遍「首启种默认配置」，结果同一台机器上 CLI daemon 与桌面 app 可能读不同配置、连抓取模式都不一样。现在配置和它所属的数据在一起，三条路径（CLI / 桌面壳 / 系统服务）读同一个文件。

**从旧版升级**：若当前目录存在老路径 `configs/config.json`，首启会**以它为种子**（打印 `seeded … from configs/config.json`），你在仓库里的改动跟着迁移，不会被内置默认悄悄取代。

## 账号与权限

**一份人员名单，两种密码。** 控制台登录和代理出网是同一个账号的两种用途，不是两套用户系统：

| 密码 | 用途 | 存储 |
|---|---|---|
| **账号密码** | 登录控制台 / CLI 登录 | argon2id 哈希，永不回显 |
| **代理密码** | 客户端连 mixed 入站(:21584) | 明文——sing-box 自己校验它，我们没得选 |

一个人可以只有账号密码（能看控制台、不能走代理），也可以两者都有。给谁发代理密码就是「谁的设备可以用这个网关出网」。

**角色只有两个**：`admin`（管理一切，含用户与远程网关的敏感信息）和 `client`（普通用户，只能看自己相关的东西 + 在本地覆盖策略，见下）。

### 首个管理员（认领网关）

**在有人认领之前，`/api/*` 是开放的**——必须如此，否则全新安装无法完成初始化。所以 `serve` 启动时会把这件事**明说**在日志里，并给出认领命令。

```bash
# 网关本机（loopback 即证明你在这台机器上，无需额外凭据）
trust-proxy auth bootstrap
# 远程/云上（不在本机 ⇒ 还需要 serve 启动时打印的一次性认领码）
trust-proxy auth bootstrap --api-addr <host>:21585 --code <启动日志里的 code>
```

浏览器同理：从网关本机打开控制台只要填用户名密码；**从别的机器打开会多一个「一次性认领码」输入框**（`/api/auth/state` 的 `needs_bootstrap_code` 告诉前端要不要问）。第一个账号**必然是 admin**——否则会出现一台没人能管的网关。

### 之后的账号

- **默认不开放注册**。admin 在 Users 页（或 `trust-proxy auth registration on`）打开后，登录页才出现「注册」。
- admin 也可以直接建：`trust-proxy user add <name> --admin`、`user passwd`、`user proxy-pass`（`--clear` 收回）、`user role`、`user disable`、`user rm`（永不删最后一个 admin）。
- **JWT 会话**（httpOnly + SameSite=Strict cookie，写操作校验 Origin）用于浏览器；**API key**（`tp_…`，只在创建时显示一次，`apikey new|ls|rm`）用于脚本和 CLI 的 `--api-token` —— `trust-proxy auth login` 就是登录一次、换一把 key 存下来给后续命令用。停用或降权**立即对已有会话生效**——中间件每次都重读账号记录，不信任 token 里的旧角色。
- `--api-token <secret>` 这种「一个静态口令」的老用法仍然支持（探针场景），与账号体系并存。

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

## 多网关：远程网关持有共享策略

**心智模型**：策略住在**远程网关**（云服务器/软路由）上，本地机器只是「把流量推过去」。这样一份配置多台机器共享，订阅链接、节点、规则都只在网关上，不复制到每台笔记本。

```bash
# 网关（云服务器）：暴露 API，第一个管理员认领它
trust-proxy serve --api-addr 0.0.0.0:21585
trust-proxy auth bootstrap --api-addr <host>:21585 --code <启动日志里的>
# 给每台要用它的机器建一个账号 + 代理密码
trust-proxy user add laptop && trust-proxy user proxy-pass laptop
```

本地机器上：Gateways 页注册该网关（URL + token/账号）→ 勾「**作为出口**」并填代理端口与它的账号密码 → 顶栏「出口」选它。本机可以进一步切成 **Client 模式**：不再自己执行策略（姿势强制 Split），只把流量交给网关——两台机器同时执行两套默认拒绝，只会互相打架。

**谁看得见什么**：

| | admin | client |
|---|---|---|
| 远程网关的 token / 订阅 URL / 节点 outbound / 代理密码 | 从不回显（连 admin 也是——服务端保存，API 只回掩码后的形状） | 同样看不到 |
| 网关注册、用户管理、姿势/模式/规则集等全局策略 | ✅ | ❌（页面不出现，直接敲 URL 也是 403） |
| 自己的连接与历史 | 全部 | 只有自己的（服务端按调用者过滤，不靠前端隐藏） |
| **本地覆盖** | ✅ | ✅ 但**只能 Deny，或把某目标改成 direct** |

**本地覆盖只有这两种是刻意的**：普通用户在本地「Permit」一个目标毫无意义——闸在网关上，本地放行不会让流量真的出去，只会让人以为自己开通了。所以 UI 里根本不给这个选项，取而代之的是**一键向管理员申请放行 + 填理由**：

```bash
trust-proxy request ask <domain> --reason "..."   # 用户提
trust-proxy request ls | approve <id> | deny <id> # 管理员批（Users 页也有）
```

待批的申请在网关上就是一条 `enabled=false` 的规则——**批准即启用**，不存在「批准了但没生效」的中间状态。

**大脑视图**：在任一控制台注册其余网关后，顶栏可切换正在**管理**哪台（大脑反代 `/api/nodes/{id}/*` 并注入各自 token，浏览器仍单 origin、不碰 token）。这与顶栏的「出口」选择器是**两件不同的事**：切换管理对象不会改变你自己的流量走向，否则打开一台远程网关的配置就会把自己的网络甩到另一个国家。

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
