# trust-proxy

出入网流量控制 / 检测 / 木马外泄识别网关，以 [sing-box](https://github.com/SagerNet/sing-box) 为数据面底座。

出网流量经 trust-proxy → **默认拒绝**（黑名单追不完，只有许可制才卡死木马向任意 C2 回传）→ **检测**异常出网（威胁情报、beaconing、DGA/DNS 隧道、异常大上传=疑似外泄、JA4 指纹）→ 经订阅或自建节点出口。

一个二进制，两种角色：

| 角色 | 命令 | 说明 |
|---|---|---|
| **网关** | `sudo trust-proxy install` | 装成系统服务：mixed 入站(:21584) + 策略 + 检测 + 控制台/API(:21585)，可切 TUN 全流量接管 |
| **代理服务端（出口节点）** | `trust-proxy proxy gen` / `proxy run` | 自建任意协议出口节点 |

## 快速开始

**一条命令**（Linux / macOS，装和升级都是这一条）：

```bash
curl -fsSL https://raw.githubusercontent.com/ivanzzeth/trust-proxy/main/scripts/install.sh | sudo sh
```

它认平台、取对应的 [Release](https://github.com/ivanzzeth/trust-proxy/releases)、把 CLI 放到 `/usr/local/bin`，然后跑 `trust-proxy install`。**再跑一遍就是升级** —— 换掉服务那份二进制并重启，策略和账号一行不动。

`TP_VERSION=v0.10.1` 钉版本，`TP_NO_SERVICE=1` 只装 CLI 先看看。

已经有二进制的话，那一条就够：

```bash
sudo trust-proxy install
```

装完就是：以 root 跑、数据在机器级目录、**开机自启**、挂了自动重启，而且**已经认领好了** —— 第一个管理员账号建好，它的 API key 写进你（`sudo` 背后那个人）的家目录，所以下一条命令不用 export 任何东西：

```
✓ installed /etc/systemd/system/trust-proxy.service
  program: /usr/local/libexec/trust-proxy
  data:    /var/lib/trust-proxy

✓ claimed as "ivan"; the API key is in /home/ivan/.config/trust-proxy/credentials.json
  the CLI works now — try:  trust-proxy status

  console: http://127.0.0.1:21585/
  remove it with: sudo trust-proxy uninstall
```

控制台 **http://127.0.0.1:21585/**，TUN 在里面一键切换（服务是 root，所以真的切得动，且有死亡开关自动回滚）。要开机就进 TUN：`sudo trust-proxy install --mode tun`。

**只有一个网关，只有一个数据目录**，机器级：`/var/lib/trust-proxy`（Linux）/ `/Library/Application Support/trust-proxy`（macOS）/ `%ProgramData%\trust-proxy`（Windows）。里面有订阅、策略、历史、`cache.db`，**以及配置本身**（`<data>/config.json`，首启从编译进二进制的默认值种下，之后就是你的，升级绝不覆盖）。家目录里唯一的东西是那份**凭据**（`~/.config/trust-proxy/credentials.json`），它是密钥不是状态。

> 早先有过「用户级网关」（`~/.trust-proxy` + `trust-proxy serve`），**已删除**。它做不了 TUN（要 root）、关掉终端就没了，而任何人 `sudo` 跑过一次，那个目录就归 root，之后非 root 的进程再也写不进去。升级时 `install` 会把旧目录里的策略**拷**过来一次（拷贝，不移动）。`serve` 还在，但它是服务管理器调用的内部命令。

从源码构建（Go 1.24.7+、Node 22+ / pnpm）：

```bash
make deps            # 首次：git submodule update --init --recursive（拉 sing-box）
make build           # 全套：控制台 → 内嵌 UI 的单二进制 → 桌面 app
                     #（机器上没有 cargo 就只出二进制并说明，服务器上正合适）
make                 # 不带参数 = 列出所有目标
```

### 账号

`install` 已经把第一个管理员建好了。它的登录密码是随机的（工作凭据是那把 API key），想从别的浏览器登录就自己设一个：`trust-proxy user passwd <你>`。

没有 `install` 的场景（比如一台已经在跑、还没人认领的远程网关）：

```bash
trust-proxy auth bootstrap <用户名>                                   # 在网关本机上（loopback 即凭据）
trust-proxy auth bootstrap <用户名> --api-addr <host>:21585 --code …  # 远程，码在启动日志里
trust-proxy auth login <用户名>                                       # 换一把 key 存到本机
```

**未认领的网关只对 loopback 开放** —— 在机器上就是凭据；从网络上只有 `/api/auth/state` 和带一次性码的 bootstrap 能通，其余一律 401。账号、两种密码（登录 / 走代理）、API key、注册开关见 [docs/operations.md](docs/operations.md#账号与权限)。

## 安全模型：Permit ⊥ Route

出网默认**拒绝**，两条正交轴永远分开：

| 轴 | 问题 | 默认 |
|---|---|---|
| **Permit** | 这个目的地能不能出网？ | 否 |
| **Route** | 已许可的流量走哪个出口？ | Final（默认 `proxy`） |
| **Deny** | 硬拒绝（优先于 Permit） | 空 |
| **Subjects** | 哪个进程/设备可出网 | 不限制 |

**铁律**：Route 永不开闸，Permit 永不选出口。第三条铁律是 **DNS 必须跟随 Route**——解析器的出网路径要和流量一致，否则国内站点会被解析到境外边缘节点再直连过去（实测 taobao 15.8s → 修复后 0.2s）。详见 [CLAUDE.md](./CLAUDE.md)。

## 桌面端

壳很薄：一个窗口加一次授权。**它不自己跑网关** —— 打开时问二进制 `env --json`，然后只有四种结局：

| 机器上是什么 | 壳做什么 |
|---|---|
| 系统服务在跑，版本一致 | 贴附，**零提示**直接进已登录的控制台 |
| 服务在跑但比 app 旧 | 「Update」按钮 —— 一次系统授权就换掉 daemon（否则升级是静默空操作：新 app 贴到旧 daemon 上，每一页看起来都对） |
| 端口上有网关但不是服务 | 「接管并装成系统服务」 |
| 什么都没有 | 「Set up」 |

三种结局都是同一条 `install`，所以都是一次系统授权、零敲命令。提权方式各平台不同（macOS `osascript` / Linux `pkexec` / Windows UAC），壳本身从不是 root。

```bash
make build-app   # .app+.dmg / .deb+.AppImage / .msi+.nsis
```

**macOS 已在真机验证**（`make e2e-macos` 在 tart VM 里跑真 launchd + 真 TUN）。**Linux / Windows 桌面尚未验证，CI 也还不出桌面包** —— 这两个平台今天请走上面那条命令行，装好之后 app 打开就是零提示贴附。细节与状态见 [docs/desktop.md](docs/desktop.md)。

**app 未签名**（也不打算签）：自己构建的双击即开；下载来的需放行一次 —— `xattr -dr com.apple.quarantine "/Applications/Trust Proxy.app"`，或系统设置 → 隐私与安全性 →「仍要打开」。

## CLI / SDK

控制台能做的，命令行都能做；每个子命令都有 `--json`，`--api-addr`/`--api-token` 可指向本机或远程探针。

```
install | uninstall | env | status | auth | user | apikey | request
acl | rules | dns | mode | routing | posture | final | profile | proxies | groups
endpoints | tun | inbound | autoblock | detect | detections | quarantine | netcheck | history
node | sub | conn | proxy gen|run|stop | service status
```

`env` 是这台机器的唯一事实源（目录、权限、`can_tun`、服务状态、跑的是哪个 build、本平台怎么提权、**下一步该干什么**）。桌面壳就是读它，不自己算。

SDK 两层：`pkg/clash`（标准 Clash API 原语，可复用于任何 sing-box/mihomo/clash）+ `pkg/client`（本项目 `/api` 的易用封装，组合 clash）；wire 类型只在 `pkg/apitypes`。

## 端口（均绑 loopback）

| 服务 | 地址 | |
|---|---|---|
| 代理入站 (mixed socks/http) | `127.0.0.1:21584` | 客户端指这里 |
| **后端 `/api` + 控制台** | `127.0.0.1:21585` | 浏览器开这里 |
| Clash API（`pkg/clash` 消费，secret 在数据目录） | `127.0.0.1:21586` | 后端内部 |

编号来历：`0x54`=`T`、`0x50`=`P` → `0x5450` = **21584**，往上连号（TP / TP+1 / TP+2）。刻意避开拥挤区间——9090 被 Prometheus / Cockpit / php-fpm / Clash 自己抢，9096 附近也满。

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
