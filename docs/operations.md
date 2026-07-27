# 运行时：配置位置 / 账号权限 / 抓取模式 / 路由模式 / 防板砖 / 检测处置 / 多网关

## 一台机器上只有一个网关

它以 root 跑、由服务管理器托管、开机自启，数据在**机器级**目录。这不是若干种部署形态里的一种，是唯一一种：

| | Linux | macOS | Windows |
|---|---|---|---|
| 数据 | `/var/lib/trust-proxy` | `/Library/Application Support/trust-proxy` | `%ProgramData%\trust-proxy` |
| 托管副本 | `/usr/local/libexec/trust-proxy` | 同左 | `%ProgramData%\trust-proxy\bin\` |
| 服务 | systemd unit | launchd LaunchDaemon | SCM |

```bash
# 全新机器 / 升级，都是这一条（认平台、取 Release、装 CLI、装服务）
curl -fsSL https://raw.githubusercontent.com/ivanzzeth/trust-proxy/main/scripts/install.sh | sudo sh

sudo trust-proxy install     # 已有二进制时：拷托管副本、注册服务、启动、开机自启、认领
trust-proxy env              # 这台机器现在是什么状态、下一步该干什么
sudo trust-proxy uninstall   # 逃生口，任何半装状态都能收干净；数据一行不动
```

`install` 是幂等的，**重跑就是升级**：换掉托管副本、重启服务，策略和账号不动。改抓取模式也是重跑它（`--mode tun`）。

> **用户级网关已删除。** 曾经可以 `trust-proxy serve` 在 `~/.trust-proxy` 里跑一个自己的：它做不了 TUN（要 root），关掉终端就没了，而只要有人 `sudo` 跑过一次，那个目录就归 root——之后非 root 的进程（比如桌面 app）再也写不进去，症状是「app 打不开」而原因在三步之外。`install` 会把旧目录里的策略 **拷** 过来一次（拷贝，不移动，已有的不覆盖）。`serve` 还在，但已隐藏：它是服务管理器 exec 的东西，不是给人敲的。非 root 直接敲它会告诉你该用 `install`。

家目录里唯一剩下的是**凭据**：`~/.config/trust-proxy/credentials.json`（0600）。`install` 以 root 跑，会把第一个管理员的 API key 写进 `SUDO_USER` 的家目录并 chown 给他——落在 `/var/root` 的密钥等于没有密钥。它是密钥，不是状态：删掉只需要重新 `auth login`，不会丢任何策略。

## 配置在哪（只有一处）

`<data>/config.json`，**首次启动自动种下**（来源：编译进二进制的默认配置）。之后那份文件就是用户的，升级**绝不覆盖**。

`-c` 只作显式覆盖（`configs/config.tun.json`、线上钉死的某份文件）。

## DNS 的默认值（改过，说明一下）

默认解析器现在是**经代理的加密 DoH**（`1.1.1.1`，`detour: proxy`），而**走 direct 的域名自动改用国内解析器**（`223.5.5.5`，由 `injectDirectDNS` 按最终路由表镜像出来）。

以前默认只有一条 `local`，也就是「交给系统 DNS」。那是三个预设里唯一**既不防泄漏也不防污染**的：
- 你经代理访问的每个域名，查询仍然明文发给运营商；
- 被墙的域名本地查回来是污染 IP，拿着它从代理出去，连不上；
- 而「DNS 跟随路由」那套机制**永不启动** —— 它只在默认解析器位于代理之后时才分流。

所以那个默认值和本项目自己的第三条铁律是矛盾的，而且没有任何地方提示。

两处刻意的取舍：
- **不带 `rule_set` 规则**（控制台「中国大陆分流」预设里有一条 `geosite-cn → direct`）。全新装机没有任何规则集，那个引用会悬空，box 直接起不来 —— 这个类别的 bug 已经发生过一次。不需要它：`injectDirectDNS` 镜像的是**最终**路由表，走 direct 的域名自然拿到国内解析器。
- **`local` 保留但不作 final**，给 `1.1.1.1` 不可达的网络留一条手工退路（控制台 DNS 页可切「系统」预设）。

没有节点时也不会把自己弄死：`detour: proxy` 指向 proxy 组，而它在没有出口时就是 `selector[direct]`；服务器是 IP，不需要先解析一个域名。

为什么收进数据目录：`-c` 原先默认 `configs/config.json`——一个**仓库相对路径**，只在 checkout 里跑才有意义。于是桌面端只能另挑位置，还各自实现了一遍「首启种默认配置」，同一台机器上两条路径可能读不同配置、连抓取模式都不一样。

**当前目录里的 `configs/config.json` 不会被采用**，只会被提一句。它曾经会：而发布包里正好带着一个 `configs/` 目录，于是解压后 `cd` 进去 `sudo ./trust-proxy install`，种子来自压缩包那份而不是编译进二进制的那份——任何恰好有同名文件的目录也一样。特权命令不该依赖你在哪个目录敲它。真要用那份就 `-c ./configs/config.json`。

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
trust-proxy auth bootstrap <用户名>          # 密码交互输入
# 远程/云上（不在本机 ⇒ 还需要 serve 启动时打印的一次性认领码）
trust-proxy auth bootstrap <用户名> --api-addr <host>:21585 --code <启动日志里的 code>
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
# 网关（云服务器）：装成服务并暴露 API。在机器上跑，所以它自己就认领好了
sudo trust-proxy install --api-addr 0.0.0.0:21585
# 给每台要用它的机器建一个账号 + 代理密码
trust-proxy user add laptop && trust-proxy user proxy-pass laptop
```

从别的机器认领一台还没人认领的网关，要启动日志里那个一次性码：

```bash
trust-proxy auth bootstrap <用户名> --api-addr <host>:21585 --code <启动日志里的>
```

**未认领 ≠ 敞开。** 空账号表时那个「谁来都是 admin」的兜底**只对 loopback 生效**——在机器上就是凭据。从网络上只有 `/api/auth/state` 和这条带码的 bootstrap 能通，别的一律 401。（这一条以前不看来源地址，而一次性码只守着 bootstrap 这一个端点，于是一台暴露出去、还没人认领的网关，根本不需要认领就能被人直接驱动整个策略 API。）

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

`tun` 入站 + `auto_route` 网络层接管全部出入网流量（木马的裸 socket 也逃不掉）。需 **root**，与其它 TUN 工具（Surge 增强模式等）互斥 → 用于专用网关机 / 软路由。检测与策略逻辑不变（同一 route）。

服务是 root，所以 TUN **随时可切**，三种等价方式：

```bash
sudo trust-proxy install --mode tun     # 开机就进 TUN
trust-proxy mode set tun                # 运行时切，默认 60s 死亡开关
```

或者控制台顶栏的 CAPTURE 开关（同一条 API，同样有死亡开关）。**死亡开关**：切过去之后不 `trust-proxy mode confirm` 就自动回滚——远程机器上切 TUN 把自己网断了还能回来，靠的就是它。

`can_tun` 由网关自己回答，UI 据此决定要不要给你按。它**不等于**「是不是 root」：Linux 上 setcap 过的非 root 二进制可以，Windows 上没提权的管理员不行。

- **容器**：Docker 加 `--cap-add=NET_ADMIN --device=/dev/net/tun`；Proxmox 非特权 LXC 需宿主放行 `/dev/net/tun`。
- **同一数据目录勿并跑两实例**（`cache.db` 是 bolt，单写锁）。`install` 会先把占着 API 端口的那个停掉再装，并且等它**进程真的退出**——只等端口释放的话，旧网关还在收尾、新服务已经起来，中间那段两个进程共用一个锁。
