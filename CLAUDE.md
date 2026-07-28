# CLAUDE.md — trust-proxy

出入网流量控制 / 检测 / 异常行为识别网关。以 [sing-box](https://github.com/SagerNet/sing-box) 为数据面底座，
核心目标是识别出入网异常，尤其**木马/后门向外部机器回传机密数据（exfiltration / C2）**。

> 部署形态：**GPLv3 开源，公开分发二进制/桌面端**。因整体链接 sing-box（GPLv3），分发物须遵守 GPLv3
> （随附对应源码、保留声明）——项目本就 GPLv3，合规即可。（早期曾设想「自用不分发→可闭源」，现已作废，详见文末「许可证」。）

---

## 开发顺序（**铁律，不得跳阶**）

任何新功能都按这条链推进，**每一阶段测试充分后才进下一阶段**：

```
功能(数据面/引擎) → API → SDK → CLI → WebUI
```

跳阶的代价就是**漏实现**：先写 UI 就会出现「控制台能点、CLI 没有、脚本调不到」的半成品；先写 CLI 再补 API 就会出现两套模型。逐层落地还有一个副作用是**每层都能独立发现上一层的错**——CLI 阶段拿真实网关跑一遍，就抓出了 `/api/customrules`、`/api/rulesets` 返回整份 store 文档而非裸数组这种只有真机才暴露的形状 bug。

| 阶段 | 落点 | 「测试充分」的判定 |
|---|---|---|
| **1. 功能** | `internal/gateway`（注入/重建）、`internal/detect`、各 store（`internal/{whitelist,customrules,ruleset,dnscfg,…}`） | 该包单测 + **`make build-go && ./trust-proxy selftest`**（VM 里 `sudo` 跑覆盖 tun；`build-go` 是不带 UI 的快速内环，`make build` 才是出全套）。涉及安全语义的必须新增 selftest 场景，并**验证去掉修复后该场景会 FAIL**（测试得有牙齿） |
| **2. API** | `internal/api`（路由 + 入参校验 + **失败回滚**，别让一条坏数据 brick 网关） | handler 单测（`internal/api/*_test.go`）+ 对真实实例 curl 一遍；错误必须以 `{"error":…}` 透出，不能静默成功 |
| **3. SDK** | `pkg/client`（每个端点一个薄方法，wire 类型只放 `pkg/apitypes`，**不建第二套模型**）；底层 Clash 原语在 `pkg/clash` | `httptest` 假后端断言 method/path/body/token（`pkg/client/policy_test.go`）。**注意返回整份 store 文档的端点要解包** |
| **4. CLI** | `cmd/*.go`（cobra，走 SDK 而非直接拼 HTTP）；每个命令必须有 `--json`，共享 `--api-addr`/`--api-token` | VM 里对真实网关跑通，且**每个写操作用另一个命令读回来**验证（no-proxy 不能顺带授予 Permit 这类轴隔离要显式断言）；危险开关要确认提示 + `-y` |
| **5. WebUI** | `dashboard/`（页面 + `src/lib/api.ts` 类型 + `src/i18n/pages/*.ts` 的 en/zh 双语） | `npx tsc --noEmit` 通过 + 页面实操；只连 `:21585` 单一 origin，浏览器不碰 secret |

**跨阶段规矩**：
- 发现上游阶段设计不对，**回那一层改**，不要在下游打补丁（例：CLI 里 workaround 一个畸形 API 响应＝把技术债搬到最末端）。
- 每阶段收尾都要更新本文件对应段落（新端点、新命令、新坑），文档滞后视为该阶段未完成。
- 只读能力（列表/查看）与写能力（增删改）一起交付，否则用户看得见改不了。

---

## 架构

**单进程**：我们自己的 Go `main` 以库方式 `import` sing-box，一个二进制同时是数据面 + 控制面 + (未来)检测面。

```
                         我们的二进制 (github.com/ivanzzeth/trust-proxy)
  客户端 ──socks/http──▶ ┌─────────────────────────────────────────────────┐
     :21584             │ sing-box 核心 (route / sniff / 连接跟踪)          │──direct/代理──▶ 出网
                        │      │                         ▲                  │
                        │      │ AppendTracker           │ internal/api     │
                        │      ▼                         │ (+ 代理 Clash)   │
                        │  检测引擎                我们的控制台 dashboard/  │◀── 浏览器 :21585
                        │  信誉/beacon/外泄/DGA/JA4  (React, /api 单 origin)│
                        └─────────────────────────────────────────────────┘
```

三层职责：

| 层 | 现状 | 实现 |
|---|---|---|
| **数据面** 代理/路由/分流/连接跟踪 | ✅ sing-box 原生 | `configs/config.json` 的 route 规则；**白名单默认拒绝**（allow-list 放行 + 末尾 `reject` 兜底）；`sniff` 取 SNI |
| **控制面/UI** | ✅ | 自研控制台 `dashboard/` + `internal/api`（:21585 单一 origin；连接/代理组/日志由后端代理 Clash API） |
| **检测面** 异常/外泄识别 + 处置 | 🟡 里程碑 1（遥测 stub 已跑通） | `detector.go` 实现 `adapter.ConnectionTracker`，经 `Box.Router().AppendTracker` 挂上；当前记录每条放行连接，后续长检测算法 + 处置（wrap-close / Clash `DELETE /connections/{id}`） |

### 订阅 → apply（热重载）
- `internal/subscription`：抓取订阅 → 解析成节点（每个带完整 sing-box outbound JSON）。解析支持：① **sing-box JSON**（直取 outbounds，无损）② **Clash YAML**（`proxies:` → outbound，见 `convert.go` 的 `clashProxyToOutbound`）③ base64/明文 **share 链**（vless/trojan/ss/vmess/hysteria2/tuic）。协议均覆盖 reality/tls/utls + ws/grpc。
- **抓取来源**：http(s) URL，或 **`file://本地路径`**（`sub add file:///...`，绕过网络）。
- **WAF / 客户端指纹（已解决）**：部分机场做 TLS/HTTP 指纹识别，只放行 mihomo/clash/浏览器——curl 得风控页、裸 Go `net/http` 被 reset(EOF)。解决：`internal/subscription/fetch.go` 用 **uTLS 伪装 Chrome 指纹**（`metacubex/utls` HelloChrome_Auto，自动 h1/h2），trust-proxy **自主抓取无需外部工具**。已实测 JA4=`t13d1516h2...`（真 Chrome 指纹）。
- **兜底**：仍支持 `sub add file://` 从本地文件导入（如 clash-verge 的 profile，macOS: `~/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles/*.yaml`），用于极端 WAF 或离线场景。
- **UA 门控**：默认 UA=`clash-verge/v2.0.0`，可 `sub add --ua` 覆盖。**部署在机房时抓订阅会被 hosting-IP 拦**（未来用 `--via <节点>` 经已有节点抓）。
- `gateway.Manager.Apply(nodes)`：JSON 层把节点 outbound 注入配置、把 `proxy` 组重建为 `urltest`（0 节点则退回 `selector[direct]`）→ `buildBox`(fresh ctx+parse+New+AppendTracker) → **先建新 box 成功才关旧的**（配置错误则旧 box 完好、apply 报错，不中断服务）→ Start 新 box。约束：sing-box 库模式无粒度热更，reload=重建实例，重建期间监听端口有短暂 blip。
- **apply 后**：白名单放行的流量走 `proxy` 组（即经订阅节点出网）。apply 死节点会导致放行流量断（urltest 无健康节点）；重启 serve 回到 base（proxy=selector[direct]）。

### 安全模型：Permit ⊥ Route（Strict / 默认拒绝）

出网默认**拒绝**。两条正交轴，永远分开：

| 轴 | 问题 | 默认 | 谁写入 |
|---|---|---|---|
| **Permit** | 这个目的地能不能出网？ | 否 | Policy → Permit；`role=permit(+route)` 规则集；custom/pack `Permit=true` |
| **Route** | 已许可流量走哪？ | Final（默认 `proxy`） | Policy → Route（no-proxy）；`route-*` 规则集；custom egress；Final |
| **Deny** | 硬拒绝（优先于 Permit） | 空 | Policy → Deny；`role=deny` 规则集 |
| **Subjects** | 哪个进程/设备可出网 | 不限制 | Policy → Subjects（进程/设备 L1 invert） |

**铁律**：Route 永不开闸；Permit 永不选出口；Final 不能打开空闸。China-direct = 仅 `route-direct`；要让大陆站出网须另开 **China (wide)**（`permit`，有安全警告）或逐条 Permit。

sing-box 层写法（顺序敏感）：sniff → L1 reject → L2 Global → L3 倒置许可闸 → L4 有序 egress → catch-all（`network` matcher 必需）。闸用 `route→blocked` 而非 `reject`，以便 tracker 仍见被拦连接 + SNI（可一键加白）。

**运行时注入分层**（`buildMergedConfig` / `injectAllow`）：

| 层 | 规则 | 注入 |
|---|---|---|
| **L0** | `source_port ∈ mgmt → direct` | `injectManagement` |
| **L1** | 黑名单 / deny 规则集 / 进程·设备 invert → `reject` | `injectBlacklist` + `injectRuleSets` + `injectProcessDeviceFloor` |
| **L2** | `clash_mode=Global → proxy`（地板下、闸上） | `injectClashModeGlobal`（须先于 `injectAllow`） |
| **L3 Permit 闸** | `NOT(permit-set) → blocked` | `injectAllow` |
| **L4 Route** | custom → no-proxy → `route-proxy` RS → `route-direct` RS | `injectAllow` |
| **catch-all** | 有闸 → Final；无闸 → `blocked` | `injectAllow` |
| **L5 DNS 跟随路由** | 镜像最终路由表 → `direct` 的域名用 `dns-direct` 解析；`proxy` 的域名用远端解析器 | `injectDirectDNS`（在 `applyInvariants` 里最后跑） |

**DNS 必须跟随 Route（第三条铁律）**：解析器的**出网路径**要和流量的出网路径一致。远端解析器（`detour:proxy` 的 DoH）在**出口节点所在地区**看世界，它给国内 CDN 的答案是韩国/印度/新加坡边缘节点——再按 `geosite-cn → direct` 直连过去，等于「中国→韩国→中国」，国内站点 TLS/首字节 0.8～16s（实测 taobao 15.8s）。故 `injectDirectDNS`：① 合成 `dns-direct` 服务器（无 detour ⇒ 走 direct，默认 `223.5.5.5`，`direct_server` 可改）②把最终路由表按顺序镜像成 `dns.rules`（用户自建规则优先，镜像只补空白）③给每个**会自己拨号的 outbound**（`direct` + 各节点协议）钉 `domain_resolver: dns-direct`——TUN 下 `override_destination` 重解析走的就是这一跳；节点主机名（如 `isp.decodo.com`）也不再「经自己解析自己」而死锁。仅当默认解析器 `detour=proxy` 时才启用（`local`/直连解析器本来就一致）；`disable_direct_split` 可关。GFW 污染不是问题：只有**走 direct 的域名**才用国内解析器。

**许可集（L3）** = 白名单域名/IP ∪ `RuleRoleGrantsPermit` 规则集 ∪ custom/pack `GrantsPermit()` ∪（闸已开时）私网 CIDR。**不含** no-proxy、`route-*` only。空许可集 → 不建闸 → 全拒。

规则集角色：`deny` | `permit` | `route-direct` | `route-proxy` | `permit+route-direct` | `permit+route-proxy`（旧 `allow-*`/`block` 启动时迁移）。共享 tag（如 geosite-cn）在包 apply/delete 时按轴 Merge/Subtract。

**锚点**：地板 reject 在 `preludeLen` 后；闸/路由/Global 在 `catchAllIdx` 前。

### UI 分工（已决策 + 已落地）
- **我们自建的控制台 `dashboard/`（shadcn/ui + Tailwind v4 + React 19 + Vite）** 是唯一 UI，由后端 `internal/api`（:21585）从 `dashboard/dist` serve，`make build-ui` 构建。**浏览器只连 :21585 单一 origin**，一切走 `/api/*`；连接/代理组/日志都由后端**代理 Clash API**（浏览器不碰 Clash secret）。HashRouter，无需 SPA 服务端兜底。
  - 页面：Overview / Connections（全部·活动·已关闭 + 一键加白）/ Nodes（订阅/粘贴 + **自建出口对话框**）/ Profiles（**当前策略实时快照** + 三步引导 + 覆盖·激活确认）/ **Policy**（Permit / Route / Deny / Subjects）/ **Rules**（Routing 生效视图 + Rule Sets + Custom/策略包）/ Proxies / Endpoints/VPN / Settings / DNS / History / **Gateways / 多网关**（原 Fleet，`/fleet` 路由不变；「节点」留给代理节点，网关叫网关）/ Logs。（`/whitelist`·`/blacklist`→`/acls`，`/rulesets`·`/custom-rules`→`/rules` 重定向。）
  - **（历史）曾 vendored Yacd 作底座（`console/`），里程碑 5 后整体换成自研 shadcn 应用并删除 Yacd**——不再有前端 upstream 同步负担。
- **go:embed 单二进制（✅）**：默认构建从磁盘 serve `dashboard/dist`（开发）；`make build-embed`（或 `-tags embed_ui`，见 `embed_ui.go`）把前端嵌进二进制，release 单文件自带 UI（`internal/api` 的 `consoleHandler` 用 `fs.FS`：embed 优先、否则 `os.DirFS(--console)`）。

**为什么单进程**：深度检测（挂 tracker、镜像连接、自定义 outbound）必须和 sing-box 同进程；
纯元数据检测才可跨机。将来若要「一个控制台管多节点」，用「探针(数据面)+大脑(分析/UI)」分离，探针仍是本二进制。

### 一台机器一个网关（**铁律**）

网关以 **root/SYSTEM** 跑、由服务管理器托管、开机自启，数据在**机器级**目录（`/var/lib/trust-proxy` / `/Library/Application Support/trust-proxy` / `%ProgramData%\trust-proxy`）。这不是若干形态里的一种，是唯一一种，入口只有 `sudo trust-proxy install`。

曾经还有一种「用户级网关」（`~/.trust-proxy` + `trust-proxy serve`），**已删除**。它做不了 TUN（要 root）、随起它的终端/窗口而死，而只要有人 `sudo` 跑过一次，那个目录就归 root——之后非 root 的进程（桌面壳）再也写不进去，症状是「app 打不开」而原因在三步之外。「macOS 能用、Linux 一碰就炸」就是它：Linux 上 TUN 基本只能 root，所以那条被污染的路径是常态而不是边角。

由此派生的规矩：
- `paths.Data()` 是唯一数据目录，`paths.UserData()` **不存在**。家目录里只剩**凭据**（`paths.CredentialsFileFor`），是密钥不是状态。
- `serve` 是 hidden 的，它是服务管理器 exec 的东西。非特权直接敲它会指向 `install`。`--data` 只作运维/测试覆盖。
- `install` **幂等，重跑就是升级**（换托管副本 + 重启服务）；它要**把活干完**——收编旧数据、注册服务、等它应答、认领并把 API key 交给 `SUDO_USER`。半装的机器不算装好。
- 任何会 refuse 的检查都排在任何写操作**之前**。（踩过：console 检查排在种配置之后，于是被拒绝的 install 仍留下一个 config.json，害得下次收编被跳过。）

### 单一二进制 + CLI/SDK 分层
一个二进制既是网关也是 CLI 客户端，靠子命令区分：
- `install` / `uninstall` — 把网关装上这台机器 / 拆干净（本地、特权，不接受 `--api-addr` 指向别处）。
- `env` — **这台机器的唯一事实源**：目录、权限、`can_tun`、服务状态、端口上跑的是哪个 build、本平台怎么提权、以及 `action`（下一步该干什么：attach/update/takeover/install/repair/unsupported）。桌面壳只读它，不自己算——壳里长出第二份「文件放哪」的判断，是这个项目最贵的一类 bug，因为壳出错时只会显示一个启动页。
- `serve` — 跑网关本体（hidden，服务管理器用）。
- 其余子命令 = **CLI 客户端**，经 **Go SDK** 调运行中的后端。

**SDK 两层**（回应「先封装标准接口为底层原语，上层再易用封装」）：
- `pkg/clash` — **底层原语**：直连标准 **Clash API**（`/connections`、`DELETE /connections/{id}`、`/version`…）。通用、可复用于任何 sing-box/mihomo/clash。
- `pkg/client` — **上层易用**：调我们自己的 `/api`（订阅等），并**组合** `pkg/clash`（`client.Clash` 暴露原语，`client.Connections()/Kill()` 是便捷封装）。
- `pkg/apitypes` — 共享 wire 类型（无内部依赖，避免 import 环）。

**CLI 覆盖全部 API**（控制台能做的，命令行都能做；每个子命令都有 `--json` 供脚本消费，`--api-addr`/`--api-token` 指向本机或探针）：
`install|uninstall`(**本地 root**;`service install|uninstall` 是隐藏别名,老笔记还能用) | `env`(机器事实源+`action`) | `service status` | `status` | `auth bootstrap|login|ticket|whoami|state|register|registration` | `user`/`apikey`/`request` | `acl ls|add|rm <permit|deny|no-proxy>` | `rules ls`(生效视图) `rules custom|packs|sets …` | `dns get|set`（`--direct-server` 等单项 patch，`-f` 整档替换）| `mode get|set|confirm`（`--guard` 死亡开关）| `routing get|set`(Rule/Global) | `posture get|set` | `final get|set` | `profile ls|save|activate|rm` | `proxies ls|select|delay` | `groups get|set` | `endpoints ls|add|toggle|rm` | `tun get|set` | `inbound get|set` | `autoblock on|off` | `detections ls|stats` | `history ls|stats` | `node ls|add|rm`(fleet) | `sub add|import|ls|apply|unapply|rm|refresh`（apply 可叠加多订阅合并进 proxy 组） | `conn ls|kill`(底层 Clash 原语→:21586) | `proxy gen|run|stop`(**本地离线**,不经 SDK——出口机上没有网关在跑；`--json` 与 `POST /api/proxy-gen` 同形)。
**坑**：`/api/customrules` 与 `/api/rulesets` 返回的是**整份 store 文档**（`{"rules":[…]}` / `{"sets":[…]}`），不是裸数组——SDK 里 `customRulesDoc`/`ruleSetsDoc` 负责解包（`pkg/client/policy_test.go` 有回归）。

### 桌面端（macOS 切片，✅）

`desktop/`：**Tauri v2 壳 + Go 网关做 sidecar**。壳里没有任何策略/检测逻辑——它是一个窗口加一段生命周期，
UI 就是网关自己在 `:21585` serve 的那个控制台（故 sidecar **必须**是 `embed_ui` 构建，`.app` 里没有 `dashboard/dist`）。

**壳不跑网关。** 它曾经会：没人应答就以登录用户身份拉起 sidecar。那个网关是假的——没有 TUN、关窗即死、还往家目录写文件，于是真正的 root 安装再也没法和它共处。整条路径（`spawn_gateway`、子进程状态、`--exit-with-pid`、那段「你的数据目录不可写」的道歉信）已删除。壳要么贴附系统服务，要么提议装一个。

**壳不判断，只渲染。** 全部事实来自 `trust-proxy env --json`，包括 `action` 这一个字段：

| action | 含义 | 壳给什么 |
|---|---|---|
| `attach` | 系统服务在跑且版本一致 | 直接开控制台，零提示 |
| `update` | 在跑，但**比这个 app 旧** | 「Update」按钮 |
| `takeover` | 端口上有网关，但不是托管副本 | 「接管并装成系统服务」 |
| `install` / `repair` / `unsupported` | 没装 / 装了没跑 / 本平台没实现 | 对应文案 |

四态是从「有没有人应答」一个问题扩出来的，因为那一个问题在四种情况里只对一种，而错的那两种**都是静默的**：升级后新 app 贴到旧 daemon 上（每一页看起来都对，新二进制一次没用上），以及手起的网关被永久收养、服务永远装不上。`update`/`takeover`/`install` 跑的是**同一条 `install`**（它幂等），所以都是一次系统授权、零敲命令。

壳里绝不能再长出第二份 Go 侧的规则。已经踩过三次：自己那份 `data_dir()`、自己猜 sidecar 在哪、自己拼 `install` 参数（还悄悄传了 `--data <home>`，把「root daemon 不写家目录」这条规矩整个绕过去）。壳是最坏的漂移场所——它出错时显示的是一个启动页，不是错误。

**提权不放在壳里**：TUN 要 root，GUI 不该是 root。`internal/service` + `sudo trust-proxy install`（macOS **LaunchDaemon**，
`/Library/LaunchDaemons/io.trust-proxy.gateway.plist`）让 **launchd 拥有 daemon**，壳只贴附；壳上的按钮就是拿一次
管理员授权（`osascript ... with administrator privileges`）去跑这条 CLI。
**plist 绝不指向 `.app` 内部**（第三条防板砖）：install 把二进制拷到 **`/usr/local/libexec/trust-proxy`**（root:wheel，
临时文件→chmod/chown→sha256 校验→rename）再写 plist——否则 app 被拖进废纸篓/升级替换后，`KeepAlive` 会每次开机
重启一个不存在的程序，只写日志不报错。按内容拷贝还顺带丢掉 `com.apple.quarantine`（xattr 不属内容），治了
未公证 sidecar 被 SIGKILL。`uninstall` 先读 plist 的 program 再删，**只删我们那份托管副本**；`--keep-binary-path`
留给 Homebrew 这类稳定路径；`service status` 显式报 `program_missing`。防板砖同调：`uninstall` 一条命令、
任意半装状态都能收干净且幂等、**数据一行不动**；install **不会顺手打开 TUN**（`--mode` 不给就不写）；`RunAtLoad`+`KeepAlive`（kill -9 后自愈）。
plist 里所有路径必须绝对（launchd 不解析相对路径，否则每次开机静默失败）。

构建：`make build`（一键全套：控制台 → embed_ui 单二进制 → `.app` + `.dmg`；没有 cargo 的机器只出二进制并说明）/ `make build-app` 只重打 app / `make desktop-dev`。**默认目标故意是「全套」**：旧的 `make build` 产出不带 UI 的二进制，装成服务后每页都是「dashboard not built」——不假思索敲的那个名字必须是不会出错的那个。
**默认 ad-hoc 签名**（`APPLE_SIGNING_IDENTITY ?= -`）：Apple Silicon 上没签名的 Mach-O 压根跑不起来，而不给 identity
时 Tauri 不封印 bundle、`spctl` 连评估都做不了（`code has no resources…`）；ad-hoc 后是
`flags=0x10002(adhoc,runtime)` + Sealed Resources，hardened runtime 已开，换真证书不改流程。签名/公证全流程与
**未签名分发怎么让别人打开**见 `docs/release-macos.md`。**实测差异**：隔离标记下命令行跑 sidecar，
macOS 15.7.7 正常、**macOS 26.4.1 直接 SIGKILL（exit 137）且日志为空**——批准 app 不顺延到它启动的二进制，
故壳自查隔离标记并把 `xattr -dr com.apple.quarantine <bundle>` 连路径打到界面上（`quarantine_hint`）。首启把内置默认配置写进
`<data>/config.json`，**已存在则绝不覆盖**（那是用户的东西）。启动失败时把网关日志里的最后一条错误**原样引到界面上**
（最常见的就是 21584 被别的代理占了，说清楚十秒能修，指一个日志路径不能）。

### 关键文件 / 目录
```
main.go                    thin: cmd.Execute()
cmd/{root,serve,sub,conn}.go  cobra 命令
internal/gateway/          box 引导 + detector + 热重载注入(outbounds/mode/whitelist/rule_set/no-proxy/customrules) + ApplyProfile + `Manager.EffectiveRules()`(从各 store 推导 L0..L4 生效策略视图,`/api/effective-rules`;`memberTags` 单一来源给 node tag 命名+自愈校验)
internal/detect/           检测引擎（含 **query.go 查询级观测**：NXDOMAIN 扫描/单父域查询速率/TXT·NULL·ANY 载荷型记录，窗口计数、阈值可配）（事件环形缓冲 + 字节计数 + 威胁情报匹配 + 持久化恢复）；**阈值全部可配**（`ApplyConfig`，见 internal/detectcfg）；exfil 需「形状」而非只看字节（上传/下载比 或 首见目的地）；`SetDisposalReady` 让处置等 Permit 索引就绪
internal/detectcfg/        检测阈值持久化（data/detection.json；beacon/DGA/exfil/处置四组，Validate 拒绝会让检测形同虚设的取值）→ `/api/detection-config` + `trust-proxy detect get|set` + Detection 页
internal/quarantine/       **网关自行封禁**的目的地（data/quarantine.json，与 posture 无关）；`injectQuarantine` 与黑名单同在 L1 地板，但独立存储——切 Strict/Split 或激活 Profile 会整份替换 deny 列表，防御性封禁不能跟着消失
internal/threatfeed/       威胁情报 feed 加载器（abuse.ch，定时刷新 → engine.SetFeedThreats）
internal/ruleset/          规则集存储 + 公开规则库 catalog（JSON 存 data/rulesets.json）
internal/profile/          配置档存储（快照订阅/白名单/规则集/模式，data/profiles.json）
internal/dnscfg/           DNS 解析策略存储（servers/rules/strategy + fakeip/hosts + **direct_server/disable_direct_split** → 注入 sing-box dns 块，data/dns.json）
internal/blacklist/        出网黑名单（域名/关键字/正则/IP → reject，injectBlacklist 注入在 sniff 之后、白名单之前）
internal/directlist/       no-proxy 旁路（域名/IP → direct，**仅 L4 Route**，不开闸；私网段引擎内置）
internal/proxygroups/      代理分组（Config{AutoCountry,ExcludeCountries,Groups}）+ 国家解析(country.go：旗emoji/中英/国码→ISO)；injectOutbounds 据此建 Auto(urltest全部)+**🌏 Overseas 共享组**(urltest,成员=国家∉ExcludeCountries 的节点;**仅当排除真的去掉≥1节点才建**,否则 Auto 已安全、指向它的规则 self-heal 回 Auto)+按国家 urltest 组+用户组(select/urltest,filter country/regex/manual)，proxy 改 selector(default Auto)。**Overseas 组**是「地区受限服务 failover」的载体:Anthropic/OpenAI 拒 HK/CN,geofenced 包(Claude/OpenAI/Cursor)走 Overseas→在允许地区间自动切、绝不落被封地区。ExcludeCountries 默认 HK/MO/CN(`DefaultExcludeCountries`,旧 store 加载时一次性迁移;nil=未设→填默认、非nil空=不排除),Proxies 页可改。sing-box 只有 selector/urltest,无 load-balance
internal/policymigrate/    Permit⊥Route 一次性迁移（allow-*→permit+route-*；directlist 拷入 whitelist；profiles v2）
internal/customrules/      有序策略规则（Permit 与/或 Egress 正交；L4 有序；node self-heal）+ **策略包**（`presets.go`：Claude/OpenAI/Cursor/…；**China (wide)=permit** + **China-direct=route-direct** 拆开；共享 tag 时 Merge/Subtract；Overseas 给地区受限服务）
internal/inbound/          入站鉴权（mixed users，applyMode 注入）——凭据由 `internal/users` 派生（`ProxyCredentials()`），控制台没有独立的「入站账号」编辑器
internal/tuncfg/           TUN 高级选项（stack/mtu/strict_route/exclude·include_package，applyMode 用）
internal/endpoints/        WireGuard/Tailscale 出口（wg-quick 解析；injectEndpoints 注入 endpoints[] + 标签加入 proxy 组）
internal/history/          每条完成连接的持久化历史（append JSONL + 聚合，detect.SetOnFinalize 喂）；**读路径按需读**（`read.go`：无过滤时只倒读活动文件尾部、total 走增量行数缓存；有过滤时先对原始行做 `bytes.Contains` 预筛、只解析候选——控制台每 5s 轮询一次，旧实现每次全量解析 45MB≈302ms，现在同规模 310µs）；轮转/保留交给 **lumberjack**（`--history-max-size/-keep/-max-age/-compress`），已轮转的代仍可在 History 页翻阅（`rotatedFiles()` glob + 透明解 gz；压缩是异步的，同一代会短暂出现 `.jsonl` 与 `.jsonl.gz`，故按代去重）
internal/ja4/               **JA4 TLS 客户端指纹**（按 FoxIO 规范：`(proto)(ver)(sni)(密码数)(扩展数)(alpn)_sha256(密码)_sha256(扩展+签名算法)`，GREASE 全程忽略，扩展哈希排除 SNI/ALPN）。fork 的嗅探器保留原始 ClientHello（`adapter.InboundContext.TLSClientHello`，上限 8KiB）——Go 的 `tls.ClientHelloInfo` 拿不到扩展列表，而扩展正是指纹的主体。**为什么要它**：ECH 之后 SNI 变成 cover 域名，基于域名的 Permit 闸失去输入，而指纹刻画的是「用什么栈」，不受影响
internal/netwatch/          **主机侧观测**（只读，不改任何系统状态）：走 BSD route socket 读路由表（不 shell out netstat），识别「隧道起来之后新出现、又能带走公网流量的非隧道路由」= TunnelVision(CVE-2024-3661) 形状；`IsLocal` 给引擎判断「这个私网地址是不是真的在本机某个接口的子网里」= TunnelCrack LocalNet 形状。**坑**：① 机器上可能有多个 utun（Tailscale 等），必须按**我们 tun 自己的地址**（`gateway.TunPrefixes()`）认自己，不能按名字；② sing-box 每次直连拨号都会经物理网卡装一条 /32 逃逸路由——实测三个直连连接就产生 5 条，默认**不报 host route**（`route_watch_host_routes` 可开），否则真信号会被淹没
internal/logging/          日志栈：**zerolog**(编码) → **diode**(无锁 ring,不阻塞写者) → **lumberjack**(轮转/保留/gzip)；daemon 下把 fd 1/2 重定向进同一个 ring 以收走 sing-box 自己的行
internal/nodes/            多网关注册表（data/nodes.json；反代 /api/nodes/{id}/* → 各探针 /api，注入 token）。每条既可以是**管理对象**也可以是**出口**（`AsExit`+`ProxyHost/Port/User/Pass` → socks outbound 进 proxy 组）；`local` 是本机自己那条（Gateway/Client 模式）。`Public()` 剥掉 token/代理密码——**连 admin 也拿不到**，服务端保存、API 只回形状
internal/users/            账号registry（data/users.json，**唯一写者是运行中的 API**）：角色 admin|client、argon2id 账号密码、**明文代理密码**（sing-box 自己校验，没得选）、API key（存 sha256，`tp_` 前缀）、`Settings.AllowRegistration`。入站多用户就是这份名单里「有代理密码的人」——不存在第二套用户系统
internal/authn/            会话：HS256 JWT（钉死 alg + issuer）、httpOnly+SameSite=Strict cookie、off-loopback bootstrap 的一次性认领码
internal/paths/            每个 OS 想把文件放哪，只有这一处答案：**Data()**（唯一数据目录，机器级：/var/lib、/Library/Application Support、%ProgramData%；**没有 UserData**）/ CredentialsFileFor（家目录里唯一的东西，是密钥不是状态）/ LegacyUserData（只给 install 一次性收编）/ Owner+InvokingOwner+LookupOwner（这次提权是替谁做的——凭据落在 /var/root 等于没有凭据）/ ManagedBinary（**有测试断言它绝不在 .app 内部**）/ Privileged / **CanTUN**（≠ root：setcap 过的 Linux 非 root 可以，UAC 下未提权的 Windows 管理员不行）
internal/credentials/       CLI 的 API key（~/.config/trust-proxy/credentials.json，0600，按 api-addr 分条）。每条带 **gateway_id**：凭据文件第一版就是因为会陈旧被删掉的，而陈旧的解法是**认出它**（「这台网关被重装过」vs「你的 key 被吊销了」是同一个 401、相反的建议），不是让所有人永远 `eval "$(… | grep ^export)"`。root 写别人家目录时 chown（只 chown 自己创建的目录）
internal/api/              我们自己的后端 /api（stdlib mux；订阅/白名单/规则集/配置档 CRUD + 模式/状态/自动阻断 + 代理 Clash connections/proxies/logs + serve dashboard）
dashboard/                 我们自建的控制台（shadcn/ui + Tailwind v4 + React19 + Vite，走 /api 单一 origin）
desktop/                   Tauri v2 桌面壳（macOS 切片）：src-tauri/src/main.rs 贴附/拉起/杀子 + ui/index.html 等待页；sidecar = embed_ui 的 trust-proxy
internal/service/          系统服务安装（macOS launchd LaunchDaemon；plist 生成 + bootstrap/bootout；`trust-proxy service`）
cmd/parentwatch.go         --exit-with-pid：父进程消失即自我关闭（桌面壳强退不留孤儿网关）
internal/subscription/     订阅 抓取/解析(base64+share链)/JSON 存储（借鉴 s-ui）
pkg/clash/                 底层 SDK：标准 Clash API 客户端
pkg/client/                上层 SDK：/api + 组合 clash
pkg/apitypes/              共享 wire 类型
internal/service/          装成系统服务：launchd(plist) / systemd(unit) / Windows SCM。共用一套 `Config` 与防板砖规则——托管副本（`/usr/local/libexec`，不在 .app 里）、`uninstall` 只删自己那份、install 不会顺手开 TUN。`File()`/`Program()`/`Installed()` 按 OS 分派（Windows 没有服务文件，SCM 注册本身就是安装）
configs/config.json        sing-box 配置：白名单默认拒绝 + clash_api + service/api(+dashboard)
third_party/sing-box       【我们的 fork 子模块】`ivanzzeth/sing-box` 分支 `trust-proxy`，replace 进本模块；上游 SagerNet 为 `upstream`
data/                      运行时数据（subscriptions.json 等，gitignore）
```

### 数据面能力：现成 vs 自研
- **现成（配置即得）**：按 domain/geoip/ip/port/进程/rule-set/逻辑规则分流；`reject`/`block` 阻断；主动断连；
  连接级遥测（上下行字节、SNI、进程、命中规则、出站链）。
- **自研（检测大脑）**：异常判定（C2 信誉、beaconing、异常上行、DGA、DNS 隧道）、自动处置闭环、
  流量镜像给 DPI（自定义 outbound 包 `net.Conn` + TeeReader）、DLP、限速、告警/审计/UI。

---

## 从上游同步代码

只有 **sing-box** 一个上游（曾 vendored 官方 dashboard 到 `webui/`，已删除——我们自研控制台后它只是个占端口的摆设）。

### sing-box（`third_party/sing-box`）— 我们的 fork 子模块（唯一上游）

子模块指向 **[ivanzzeth/sing-box](https://github.com/ivanzzeth/sing-box)** 的 **`trust-proxy`** 分支（可在 fork 上改 urltest 等）。  
SagerNet 官方仓库在子模块里登记为 remote **`upstream`**（`testing`），用来同步上游。

**跟我们的 fork（日常开发 / 推补丁）**
```bash
cd third_party/sing-box
git checkout trust-proxy
# 改代码、commit…
git push origin trust-proxy
cd ../..
git add third_party/sing-box
git commit -m "chore: bump sing-box submodule to <ref>"
```

**从 SagerNet 上游合入（独立动作）**
```bash
cd third_party/sing-box
git fetch upstream
git checkout trust-proxy
git merge upstream/testing          # 或 rebase；解决冲突后
git push origin trust-proxy
cd ../..
go mod tidy && make build-go
git add third_party/sing-box go.mod go.sum
git commit -m "chore: merge sing-box upstream/testing into trust-proxy"
```

注意：
- **内部 Go API 无兼容承诺**（`adapter`/`trafficcontrol`/`route`）。升级后若 `main.go` 或未来的 tracker 编译失败，
  按新签名修。**能走 config(JSON) 表达的就别写死 Go 结构体**，减少受伤面。
- **remote rule_set 的 `download_detour` 在 sing-box 1.14 已 deprecated（1.16 移除）**：目前 `injectRuleSets`（`internal/gateway/gateway.go`）仍用 `download_detour: "direct"`，运行会打 deprecation 警告但功能正常。升级到 ≥1.16 时改用新的 route 级 default rule-set http client / `default_domain_resolver` 机制（届时按新 schema 调整 `injectRuleSets` 生成的 descriptor）。选 `direct` 是刻意的：默认拒绝下若经 `proxy` 组拉规则会死锁（拉不到能放行的规则）。
- **build tags**：里程碑 0 无需 tag（`service/api` 无条件编译）。要 Clash API 加 `with_clash_api`，
  QUIC 加 `with_quic`，uTLS 加 `with_utls`（见 `Makefile` 的 `TAGS`）。
- 别盲目跟 `testing` HEAD，建议 pin 到具体 commit，升级当独立动作 + 回归。


---

## 构建 / 运行 / 验证

```bash
make deps        # 首次：git submodule update --init --recursive（拉 sing-box）
make build       # 一键全套：控制台 + 内嵌 UI 的单二进制 + 桌面 app
make build-go    # 只编译 Go（不带 UI，快速内环；TAGS="with_clash_api ..." 可选）
make run         # 用 configs/config.json 启动
make build-ui    # 只构建自研控制台 -> dashboard/dist
```

**Linux e2e 分四层**（`make e2e-linux` / `e2e-policy` / `e2e-dataplane` / `e2e-fleet`，都在特权容器 pid1=真 systemd 里，全部进 CI）：

| 套件 | 覆盖 | 为什么单独一层 |
|---|---|---|
| `e2e-linux` | 服务生命周期：install → 认领 → CLI 免配置可用 → TUN 捕获 → `kill -9` 自愈 → 无 pid 文件接管 → 卸载干净 | 装不上/回不来是最贵的失败 |
| `e2e-policy` | **每一条会重建 sing-box 配置的命令**（约 20 条）：sub apply / acl / rules custom / dns / routing / final / mode / profile / posture。每步读回来确认生效 + 断言数据面还在 | 配置被 box 拒绝 = 网关不再执行任何策略。这层缺席时，「全新装机切 split 必炸」发布了才被用户发现 |
| `e2e-dataplane` | **对包的断言**：默认拒绝拦得住、permit 放行、deny 压过 permit、**no-proxy 不开闸**（两轴正交）、Global 绕闸但地板仍在、模式死亡开关自动回滚、策略活过重启与原地升级、登录轮换 key 且旧 key 立即失效 | 前两层证明「命令成功、服务还在」，都不是产品的主张。产品的主张是关于**包**的 |
| `e2e-fleet` | 多网关：远程网关持策略，本地机器经它出网 | |

**为什么 origin 用 `203.0.113.10/32 dev lo`**：私网 CIDR 在闸开时本来就在许可集里，把 origin 放在容器自己的网段上，**无论策略怎么写都能连通**——每条断言都会通过，什么也没证明。TEST-NET-3 不是私网，闸对它生效。
**容器没有外网**（`raw.githubusercontent.com` 只解析出 IPv6 且无 v6 路由），所以远程规则集下不下来：`posture set split` 只能断言「失败原因不是我们自己造的配置错误」，不能断言切换成功。

**端到端自测（`cmd/selftest.go`，`trust-proxy selftest`，hidden 子命令）**：**离线、确定性、可扔进 VM 跑**的核心引擎 e2e。自起两个本地「origin」（direct-origin 返回 `direct` / node-origin 返回 `node`）+ 一个 http CONNECT「node」上游，用**真实 `gateway.Manager`** 跑遍：默认拒绝拦截 / 白名单→node / no-proxy→direct / 黑名单胜 / 自定义规则 direct·proxy·block·node / system 模式；`sudo trust-proxy selftest` 额外覆盖 tun（loopback 不被 tun 捕获，故 tun 分支只断言 box 能在 tun 模式起来）。任一场景失败则非零退出。**改引擎后务必 `make build-go && ./trust-proxy selftest`**（VM 里 `sudo` 跑覆盖全部）。

**配置只有一处**：`<data>/config.json`，**首启自动种下**——种子是 `main.go` 用 `go:embed` 编进二进制的 `configs/config.json`（仓库里就这一份，不存副本故不会漂移）。`-c` 只作显式覆盖。**cwd 里的 `configs/config.json` 只会被提一句，绝不采用**：它曾经会，而发布包正好带着一个 `configs/` 目录，于是解压后 `cd` 进去 `sudo ./trust-proxy install` 的种子来自压缩包那份——特权命令不该依赖你在哪个目录敲它。**为什么改**：`-c` 原先默认 `configs/config.json` 是**仓库相对路径**，只在 checkout 里成立，于是桌面壳只能另挑位置并在 Rust 里**重写一遍种配置逻辑**——同一件事两份实现、两个默认值，同机上 CLI daemon 与 app 会落到不同配置（连 mode 都不同）。修法是回上游改 `serve`（`cmd/configseed.go` 的 `resolveConfig`，`serve` 与 `service install` 共用），Rust 侧那份删掉。

**数据目录**：唯一一个，机器级（`paths.Data()`）。含 subscriptions/whitelist/blacklist/events/history + **`cache.db`（clash mode/urltest/rule_set 缓存）** + `ts-<tag>`（Tailscale 状态）+ `clash-secret` + `jwt-secret` + `users.json` + `config.json`。`cache.db`/`ts-*` 的路径由 `gateway.Manager.dataDir` 注入。`--data` 是运维/测试覆盖，不是部署形态。**从旧的 `~/.trust-proxy` 升级**：`install` 自动收编一次（只拷 `*.json` 策略；`cache.db` 单写锁、pid/log 属于别的进程、`jwt-secret`/`clash-secret` 是这次安装自己的，都不拷）。
**后台守护**：`serve --daemon`（`-d`）re-exec 脱离终端（`daemonize`，`TP_DAEMON=1` 标记子进程），`--log`/`--pid` 默认 `<data>/serve.{log,pid}`；停止 `trust-proxy proxy stop --pid <data>/serve.pid`（`proxy stop` 通用杀 pid 文件）。同目录勿并跑两实例（`cache.db` 单写锁）。

**日志（`internal/logging`）**：`zerolog` → `diode` → `lumberjack`，全部用现成库，不手搓。轮转参数：`--log-max-size`(MB,默认 32)、`--log-keep`(默认 3)、`--log-max-age`(天,0=只按个数)、`--log-compress`(默认开)；`--log-max-size 0` 关闭轮转。
**为什么中间要有 ring**：sing-box 的 logger 是**在连接协程里同步 `writer.Write()`**（`log/observable.go`），info 级别每条连接/每个 DNS 应答一行——直接落盘等于每个连接付一次磁盘写，轮转（rename+gzip）还会卡转发。diode 把它变成无锁 ring push（实测 1889 ns/op → 203 ns/op，18 并发），ring 满了**丢日志并报告条数**，绝不对流量施加背压。
**为什么要重定向 fd 1/2**：sing-box 不给注入 writer（只有附加式 `PlatformLogWriter`，停不掉它对 stderr 的同步写），所以 daemon 子进程把 fd 1/2 换成 pipe（热路径只剩一次内核 memcpy）再汇入 ring。前台运行不接管 stdio——终端本身就是日志。

验证（不影响本机 Surge：无 TUN、不改系统代理、端口错开）：
```bash
curl -x socks5h://127.0.0.1:21584 https://api.ipify.org          # 代理出网
curl -x socks5h://127.0.0.1:21584 https://ads.doubleclick.net    # 命中黑名单 -> 连接失败(reject)
curl -x socks5h://127.0.0.1:21584 https://example.com            # 正常 -> 200
# 浏览器打开 http://127.0.0.1:21585/
```

| 服务 | 地址 |
|---|---|
| 代理入站 (mixed socks/http) | `127.0.0.1:21584` |
| 后端 /api + 控制台 | `127.0.0.1:21585` |
| Clash API（后端内部消费，secret 在数据目录） | `127.0.0.1:21586` |

**端口为什么是这三个**：`0x54`=`'T'`、`0x50`=`'P'` → `0x5450` = **21584**，往上连号（TP / TP+1 / TP+2）。原来的 9090 是重灾区（Prometheus、Cockpit、php-fpm status、Clash 自己都用它），9096 也在拥挤区间；21584-21586 在注册端口的稀疏地带，不撞任何主流工具。**曾经的 :9095**（sing-box 官方 `services[].type=api` + vendored `webui/`）已随面板一起删除。

---

## 决策记录 & 坑（已验证）

- **底座选 sing-box**：可作 Go 库嵌入、TUN 网关成熟、连接遥测现成、协议最前沿（AnyTLS/Reality）。
  mihomo 是零成本平替（同 Clash API）；Xray-core 更适合当**墙外出口节点**（Reality 原产地，MPL 许可更宽松）。
- **抗封锁策略**：靠「多协议 + 自动 failover + 换 IP」的敏捷，而非押注单一静态协议。AnyTLS 现在存活好只是「新、没被针对」，非永久。
- **官方 dashboard 走 Connect/protobuf**（`service/api`），只在 sing-box `testing` 分支 → 子模块必须跟 testing。
  想用稳定版 v1.13.x：改用 `with_clash_api` + Clash 面板（zashboard/metacubexd）。
- **域名管控是 sing-box 原生**：`sniff` 取 SNI + `domain*` 规则 `reject`，零代码。动态「按行为决定挡谁」才是自研。
- **坑：「DNS 全走出口节点」把国内站点搞垮（已修）**。为了躲 GFW 污染，早期把**所有**解析塞进 `detour:proxy` 的 DoH（`sanitizeTunDNS` 的 `tun-dns` 也是这么兜底的）。后果：`www.baidu.com→164.52.120.52`(印度)、`www.taobao.com→155.102.23.40`(韩国)、`i1.hdslb.com→61.110.192.59`(韩国)，而这些域名命中 `geosite-cn` 走 **direct**——从国内直连境外边缘节点，实测 TLS 0.85~5.3s、taobao 总耗时 15.8s；同域名国内解析器答 `111.123.42.154/183.2.172.177`(国内)。**症状是「开着网关国内站巨慢、杀掉进程立刻飞快」，与 manual/TUN 无关**（manual 下 socks 请求同样由 `direct` 出站按 `default_domain_resolver` 重解析）。修法见上「DNS 跟随路由」；回归覆盖：`gateway_dnsdirect_test.go` + `selftest` 的 `== dns follows route ==`（两个 loopback stub 解析器，谁被查到就证明走了哪条路）。
- **坑：VM 里量不出真实解析结果**。宿主机跑着 TUN 网关时，VM 的**所有** 53 端口查询都会被宿主 hijack-dns 接管（`dig @223.5.5.5` 也返回宿主 DoH 的境外答案）。故 VM 里验证 DNS 行为必须用 **loopback stub 解析器**（不出 VM、不受宿主干扰）；真实地理答案只能在宿主机上读（read-only curl/ip-api）。

## 作为代理服务器 / TUN 网关运行
同一个二进制两种角色：
- **网关**：`sudo trust-proxy install`（mixed 入站 :21584 + 检测 + 策略 + dashboard/api :21585，装成系统服务）。
- **代理服务端（出口节点）**：`trust-proxy proxy run -c server.json`；一键生成：`trust-proxy proxy gen --type <ss|vless-reality|vless|vmess|trojan|anytls|hysteria2|tuic> --server <ip> --port <p>` → 输出服务端配置 + 客户端节点（Clash dict，可直接粘进 console）。TLS 协议自动内联自签证书（客户端 skip-cert-verify），vless-reality 免证书自动生成密钥对。
  **TUN 全流量**是它的一个模式而不是另一种部署：`install --mode tun` 开机就进，或运行时 `mode set tun`／控制台开关（都带死亡开关，不 confirm 就自动回滚）。`tun` 入站 + `auto_route` 网络层接管**所有**出入网流量——木马的裸 socket 也逃不掉。与其他 TUN 工具（Surge 增强模式等）互斥，用于**专用网关机/软路由**。检测与策略逻辑不变（同一 route）。构建需 `with_gvisor`（已在默认 TAGS）。
- **里程碑 0（✅）** 全栈跑通：Go 嵌入 sing-box + 代理 + 官方监控 UI。
- **里程碑 1（✅）** 白名单默认拒绝 + `AppendTracker` 检测器 + Clash API + 单一二进制 CLI/SDK 分层 + 订阅管理 + 订阅 apply + ✅**自动处置闭环**（`--auto-block`：威胁命中 → detector 直接断连，`internal/gateway/detector.go`）。
- **里程碑 2（✅ 主体）** 自建 React 控制台 + 单一 origin + 订阅/节点管理 + 实时连接 + ✅白名单 UI + ✅检测/告警页 + ✅规则集/配置档页 + ✅侧边栏模式切换。**待做**：go:embed 单二进制。
- **里程碑 3（✅ 主体）** 检测引擎（审计 + 字节计数 + 威胁情报命中 + 大上传外泄告警）+ 告警页；代理服务端一键部署（8 协议）；TUN 全流量网关；✅**威胁情报 feed 自动加载**（abuse.ch Feodo，`internal/threatfeed`，定时替换）；✅**事件持久化**（`data/events.json` 快照，重启恢复）；✅**运行时模式切换**（manual/system/tun，`gateway.applyMode`，失败回滚）。
- **里程碑 4（✅ 主体）** ✅**规则集一键导入**（公开 `rule_set` catalog + 按 URL；block/allow-direct/allow-proxy 角色注入，`gateway.injectRuleSets` + `internal/ruleset`）；✅**配置档（Profiles）一键切换**（`internal/profile` + `gateway.ApplyProfile` 单次原子重建）；✅**按进程放行**（白名单加 `Processes` 维度 → `injectWhitelist` 生成 `process_name/process_path` + `invert:true` 拒绝规则，未知进程连接直接拒；已实测 macOS loopback 能解析进程）；✅**按设备放行**（`Devices` 维度 → `source_ip_cidr` + `invert:true`，网关模式只放行已知来源设备）；✅白名单**输入校验 + 自愈**（非法 ip_cidr 拒绝不落盘、`SetWhitelist` 失败回滚保活、加载时 `sanitize()` 丢弃非法条目——防止一条坏数据 brick 网关）。
- **JA4 指纹（✅，观测）** 一台机器上一堆浏览器里混进一个内嵌 TLS 库，就是植入物的形状；而且指纹在 ECH 之后依然有效。按调研建议**先学基线再报偏差**（`ja4_learn_minutes` 默认 24h，窗口内只记录不告警——冷启动就报「未知哈希」会在每次浏览器升级时炸一遍），已 Permit 的目的地**仍然记录但不告警**（否则基线里恰好缺了这台机器最正常的流量）。`/api/fingerprints` + `trust-proxy detect fingerprints` + Detection 页。VM 实测两个真实栈各自可辨：curl=`t13d4907h2_…`、系统 python(LibreSSL 2.8，只到 TLS1.2)=`t12d380500_…`。
- **真机复盘修的两个降噪 bug（✅）** 重启后拿 CLI 核对真实数据，抓出两处**我自己刚写的**问题：① **DoH 绕过检测没有冷却**——一台用公共 DoH 的客户端（WARP 这类）一小时打了 **614 条**告警、只涉及 2 个目标（event_id 各不相同，确认不是重复发射，就是纯粹缺冷却），跟当初 beacon 的错误一模一样；现在按 (client, endpoint) 每 `dns_bypass_realert_s`(默认 1h) 报一次。② **DGA 误报托管商生成的域名**——真机上唯一一条 DGA 命中是 `daycount-1450237091.cn-north-1.elb.amazonaws.com.cn`（AWS ELB）。修法用 PSL 的 **private 段标记**：`publicsuffix.PublicSuffix()` 对 `elb.amazonaws.com.cn`/`herokuapp.com`/`github.io` 返回 `icann=false`，这些后缀下的「注册标签」是托管商工具生成的，熵没有意义；而真实注册域（包括机场那种 `.sbs`）仍是 `icann=true`、照旧打分。顺带修了 CLI 里 `history stats` 把字节数印成 `5.426577e+06` 的科学计数法（JSON 数字解成 float64）。
- **主机侧绕过观测（✅，只观测不强制）** 调研了 [TunnelVision(CVE-2024-3661)](https://www.leviathansecurity.com/blog/tunnelvision)、[TunnelCrack LocalNet/ServerIP](https://tunnelcrack.mathyvanhoef.com/)、[ECH RFC 9849](https://datatracker.ietf.org/doc/html/draft-campling-ech-deployment-considerations-12) 与客户端 DoH 绕过后落地的一批**纯观测**能力：`internal/netwatch` 监控路由完整性（VM 实测：注入 `203.0.113.0/24 via en0` 被报出，同时三个正常直连产生的 /32 不产生噪声）、引擎侧 LocalNet 告警（`100.64.7.9` 这类落在 LAN 旁路却不在真实子网的目的地）、客户端 DoH/DoT 绕过检测（我们自己的解析器不会自报）、以及 **ECH 配置观测**（ECH 配置走 HTTPS/SVCB 记录下发，我们现在拥有解析链路所以能看见——一旦某域名启用 ECH，SNI 不再可见，基于域名的 Permit 闸对它就失效了）。`/api/netcheck` + `trust-proxy netcheck` + Detection 页。**为什么只观测**：这几类的「执行」手段（pf kill switch、收窄 LAN 旁路、剥 ECH、拦 DoH）一旦有 bug 就是**整机断网**而不是少报几条告警，属于另一个量级的风险。调研结论、我们的真实暴露面、以及真要做时**必须先就位的 7 条防板砖脚手架**（具名 anchor / 预留生路 / 死亡开关 / 独立看门狗 / `unbrick` / 默认不跨重启 / VM 里验证 `kill -9` 与重启恢复）见 **`docs/egress-enforcement-risks.md`**。
- **DNS 查询级观测（✅）** 以前检测只看「变成了连接的域名」，漏掉两种最典型的 DNS 滥用——**DGA 扫描**（绝大多数是 NXDOMAIN，只有解析成功的那一个才会被拨号）和 **DNS 隧道**（载荷就是查询本身）。fork 加了 `adapter.DNSQueryTracker` + `dns.Router.AppendQueryTracker`（与 `ConnectionTracker` 对称，在 `Exchange`/`finishExchangeAsync` 两个汇合点上报，失败也报——失败成串本身就是信号），`gateway.detector` 同时实现两个 tracker，`buildBox` 里用 `service.FromContext[adapter.DNSRouter](ctx)` 挂上。引擎按窗口计数（`internal/detect/query.go`），阈值 `query_window_s`/`query_nxdomain_burst`/`query_parent_rate`/`query_odd_type_at` 全可配，0 = 关闭该信号。**坑**：本机 hijack-dns 的查询**没有 source 元数据**，按 client 分桶会让扫描检测在单机网关上完全失效——空 client 归入 `(local)` 一个桶。`/api/dns-queries/stats` + `trust-proxy dns queries` + Detection 页；实测 TUN 下 42 条查询/40 条 NXDOMAIN，在第 30 条（阈值）报出 kind=dns，且不自动封禁（启发式只告警）。
- **检测可配置 + 处置 fail-safe（✅）** 阈值不再硬编码：`internal/detectcfg` 存 data/detection.json，`/api/detection-config`、`trust-proxy detect get|set --exfil-min-ratio/--beacon-realert-factor/...`、Detection 页三处都能改，改完直接进引擎（无需重建 box）。**exfil 判据加了形状**：单看「上传 > 10MiB」在开发机上一天 38 次全是照片同步/AI 上下文；现在要求同时**不对称**（upload/download ≥ ratio）**或目的地首见**（默认 24h 窗口），两个信号都可设 0 关闭。**处置等 Permit 索引就绪**（`RequireWarmPermit`，默认开）：`WarmPermitCache` 是异步且要拉远端规则集的，在它落地前所有规则集来源的 Permit 都读作「未许可」，此时的大上传会把你其实批准过的目的地封掉——告警照常，只是不处置（报告 fail-open、处置 fail-safe）。
- **自动封禁独立于 posture（✅）** 以前写进当前槽的 deny 列表，切 Strict/Split 或激活 Profile 会被 `alignLiveStores` 整份替换而静默消失。现在进 `internal/quarantine`（独立文件 + L1 地板注入），`trust-proxy quarantine ls|release` 与 Detection 页可查可放行。
- **sing-box 1.16 deprecation 提前处理（✅）** remote rule_set 改用 `http_client{detour, domain_resolver}`，一次性替掉 `download_detour` 和「隐式默认 HTTP client」两个 1.16 会移除的东西；顺带让 .srs 拉取也走直连解析器。
- **告警信噪比（✅）** 真机跑一天 1137 条告警里 1082 条是 beacon 噪声（GCM 推送/VSCode 更新/滴答清单/B站 API 这类正常心跳），根因两条：① `beaconReAlert=10min` **比它要检测的周期还短**——10 分钟一次的轮询于是每轮报一次，单主机一天 144 条；现在冷却期按实测周期缩放（`max(配置值, 36×interval)`）。② beacon/DGA 告警**完全不过 `isTrusted`**（`isTrusted` 原先只在 exfil 自动封禁处调用），于是你自己 Permit 过的 anthropic/cursor/googlevideo 天天报「可能外泄/DGA」。现在启发式告警一律过 Permit 闸，**威胁情报命中不受影响**（被许可的域名上了 abuse.ch 名单恰恰最该报）。注意 `trustedDest` 是调用方回调（会查 permit 缓存并自带锁），**必须在 `e.mu` 之外求值**——放进锁里会让每条连接串行等这次查找，还可能锁环。回归见 `internal/detect/noise_test.go`。
- **里程碑 5（🟡）** ✅**beaconing 检测**（同目标周期性回连、区间变异系数低 → 疑似 C2 心跳，`detect.recordBeacon`；启发式=仅告警不自动断，用 `Event.Block` 区分高置信威胁情报命中）；✅**连接页与事件页合并**（控制台单页三标签 全部/活动/已关闭 → `/connections`）；✅**被拦连接可见 + 一键加白**（兜底改 route→`block` 出站，detector 记录被拦连接 + SNI 域名；每行 `+域名/+IP/+进程/+设备` 直接 POST `/api/whitelist` 热重载放行）。**说明**：Clash API 只有活动连接（无 closed 端点），历史来自我们的检测事件——这是「看不见连接」的真因，非 bug。
- **里程碑 6（✅ 主体）** ✅**控制台整体换 shadcn/ui**（`dashboard/`：精致 SaaS 仪表盘，Overview/Connections/Nodes/Profiles/Whitelist/Rule Sets/Proxies/Logs，全部走 `/api` 单一 origin）；✅**Clash API 重做**（`pkg/clash` + `internal/api` 后端代理 `/proxies`、select、delay、`/logs`(WS→SSE)）；✅**删除 vendored Yacd（`console/`）**；✅**go:embed 单二进制**（`-tags embed_ui` 把 `dashboard/dist` 嵌入，release 二进制单文件自带 UI；默认构建仍从磁盘 serve 便于开发）。
- **里程碑 7（✅ 主体）** ✅**DNS 服务器/规则配置**（`internal/dnscfg` + `gateway.injectDNS`：typed servers local/udp/tcp/tls/https/quic + 分流 rules + strategy/final；`detour:proxy` 让 DNS 走出口节点防泄漏；校验 + `SetDNS` 失败回滚；DNS 页含预设）。这是 **DNS 隧道/DGA 检测**的前提（后续接观测：高熵子域名/异常 TXT/查询速率）。
- **里程碑 8（✅ 主体）** ✅**DGA / DNS 隧道检测**（`detect.analyzeDomain`：SLD 香农熵+数字/元音比→DGA C2；长高熵子域名标签→隧道；单父域 distinct 子域名计数→隧道/fast-flux。启发式=仅告警不自动断）。**坑**：proxy/socks 模式下 sing-box 直接按域名拨号（`outbound connection to <domain>`），**不经 DNS 路由**，故无 `lookup succeed` 日志——检测跑在 tracker 拿到的**连接域名**上（全模式可用）；基于日志观测 DNS 查询仅 TUN/hijack-dns 模式可行（后续再上）。**坑 2（已修）**：`detector.host()` 在没嗅到域名时退回目的地址，而 `Socksaddr.String()` 是 `host:port`——`cloudflare-dns.com:443` 会让引擎里所有按名字的比较（后缀匹配、DGA 标签、许可查表）静默失配。未嗅探路径（UDP、sniff 关闭的 socks）是常态不是边角，故 `host()` 用 `AddrString()`，检测侧再 `hostOnly` 兜一层。**这类 bug 只有 live 跑才暴露**（单测喂的都是干净域名），改检测器后务必在 VM 里起 `serve` 实跑。
- **里程碑 9（✅）** ✅**per-connection 流量历史持久化**（`internal/history`：detect finalize sink → append `data/history.jsonl` + 内存聚合 top talkers/24h 趋势，重启从 JSONL 重建；`/api/history{,/stats}` + History 页）。
- **里程碑 10（✅ 主体）** ✅**多节点管理（探针+大脑）**：每个 `serve` 即探针（`--api-token` 给 `/api/*` 加 bearer 鉴权，`--api-addr 0.0.0.0` 暴露）；大脑 `internal/nodes` 注册表 + `internal/api` 反向代理 `/api/nodes/{id}/{rest...}`（注入各探针 token，SSE 透传）；控制台 Fleet 页 + 顶栏 NodeSwitcher（切换后 `queryClient.clear()` 全刷）。浏览器仍单 origin、不碰 token。
- **里程碑 11（✅）** sing-box 功能对接批量补齐（workflow 顺序实现，各自 build+test 通过才 commit）：✅Clash 规则只读查看（`/api/rules`）、✅**入站鉴权**（mixed users + Settings 页）、✅**DNS fakeip/hosts**、✅**TUN 高级选项**、✅**出网黑名单**（reject 优先于白名单）。（`clash_mode` 当时故意跳过——「Global/Direct 绕过默认拒绝」需专门设计；**已于里程碑 14 安全落地**，见下。）
- **里程碑 12（✅ 主体）** ✅**WireGuard / Tailscale 出口端点**（`internal/endpoints` + `gateway.injectEndpoints`：wg-quick 粘贴解析、注入 sing-box `endpoints[]`、标签加入 `proxy` 组;secrets 服务端保存不回浏览器)。构建默认加 `with_wireguard with_tailscale`(二进制 ~75M,Tailscale 拉大依赖);已实测 WG 端点解析+注入+入组、box 接受配置。
- **里程碑 13（✅）** ✅**远程防板砖**：管理端口豁免(`injectManagement`,`--management-ports`,API 口自动加)+ 模式切换死亡开关(`SetModeGuarded`/`ConfirmMode`/`PendingRevert`,`/api/mode` guard_seconds + `/api/mode/confirm`,控制台倒计时横幅,默认 60s)。
- **里程碑 14（✅）** ✅**路由模式 Rule↔Global 开关**（`gateway.injectClashModeGlobal`：注入 `clash_mode:"Global"` 路由规则,位于**安全 floor 之下、默认拒绝兜底之上**——Global 时默认拒绝关闭、未列入流量走 `proxy` 组,黑名单/威胁/进程·设备闸仍生效;Rule 时该规则不匹配、默认拒绝照旧。sing-box 按 `EqualFold` 大小写不敏感匹配,并从规则里的 clash_mode 值自动生成 mode list）。**热切换不重建**（Clash `PATCH /configs`）;`default_mode=Rule` + `experimental.cache_file` 持久化选择;`/api/clash-mode` GET/PUT 只放行 **Rule/Global**（**拒 Direct** 防全直连泄漏,`internal/api/clashmode.go`）;`pkg/clash` 加 `Mode()/SetMode()`;控制台顶栏 Routing 分段控件 + Global 琥珀警告横幅。曾在里程碑 11「故意跳过」,现按「安全 floor 常在」原则安全落地。**注意**:cache_file 现恒开(为持久化模式),同目录勿并跑两实例(bolt 单写锁)。
- **自建出口一键化（✅）** 以前 UI 只写一句「用 `trust-proxy proxy gen` 生成，然后把客户端节点粘过来」——既假设你手边有终端，更糟的是**诱导生成两次**：出口机上跑一次 gen 得到一套密钥，控制台里握着的是另一套，永远连不上。现在 `POST /api/proxy-gen`（+ `GET /api/proxy-gen/protocols`）由网关**一次生成两半**，返回 server 配置、配对的 client 节点、share 链，外加两段部署文本（`internal/proxygen/deploy.go`：`GenCommand` 等效命令行、`InstallScript` 带 heredoc 写盘并 `proxy run -d` 的脚本；heredoc 定界符加引号，因为 SS 密钥是 base64、含 `$` 和反引号）。SDK `client.GenerateProxy/ProxyProtocols`，CLI `proxy gen --json`，控制台 Nodes 页「自建出口」对话框（生成 → 复制脚本 → 一键「添加为节点」，走 `subscription.Parse` 收单个 Clash dict）。入参校验在 API 层：server 必填且必须是裸 IP/主机名（CLI 给人看可以留 `YOUR_SERVER_IP` 占位，API 给机器用不行——占位符会被导入成一个永远拨不通的节点）。**验证**：VM 里把返回的脚本原样 `sh` 执行→服务端起在 18388，把 client 节点导入网关并 apply→Clash delay 2469ms 真出网（密钥配对的唯一硬证据）；另有 7 协议的「生成的节点能被导入器解析」handler 测试 + headless Chrome 走完整对话框。
- **真机/真浏览器才暴露的一批（✅）** 这一轮的五个缺陷全部只在实跑时现形，单测一个都没抓到：① `detector.host()` 退回 `Socksaddr.String()` 得到 `host:port`，引擎里所有按名字的比较静默失配；② `/api/subscriptions` 把订阅 URL 原样回给浏览器；③ `/api/history` 有时回裸数组有时回分页对象，`history ls` 因此一直是坏的；④ 手写配置缺 catch-all 规则 ⇒ **默认拒绝与 Final 双双静默失效**（`injectAllow` 现在会补上，并加了 `--dump-config`）；⑤ 多网关 e2e 一度**假绿**——origin 在同一网段解析到 RFC1918，被客户端的 LAN 旁路直连了，而「归属到 laptop」的断言是被一条无关的 urltest 探测满足的。教训就是 CLAUDE.md 开头那句：每阶段都要拿真实网关跑一遍。
- **POST 静默丢字段（✅）** `POST /api/nodes` 只读 name/url/token，收到 `as_exit`/`proxy_*` 直接扔掉——回 201，然后没有出口。**静默忽略比拒绝更糟**；现在 create 接受与 patch 同形的字段，patch 被拒则回滚这次注册。
- **里程碑 15（✅ 主体）** ✅**账号与权限**（`internal/users` + `internal/authn`）：第一个账号必然 admin；**认领前 /api 是开放的**（否则全新安装无法初始化），启动日志明说并给命令；off-loopback 认领要一次性码——`/api/auth/state` 因此多了 `needs_bootstrap_code`，**否则云上网关的控制台只能显示一个必然 403 的表单**（真浏览器跑一遍才发现）。角色只有 admin|client；停用/降权立即对已有会话生效（中间件每次重读账号记录，不信任 token 里的旧角色）；默认不开放注册，admin 可运行时开。**入站多用户 = 同一份名单**里有代理密码的人。
- **里程碑 16（✅ 主体）** ✅**多网关的心智模型落地**：远程网关持有共享策略，本地只把流量推过去（`AsExit` 出口 + Client 模式强制 Split——两台机器各跑一套默认拒绝只会互相打架）。**client 的本地覆盖只有 Deny / 改 direct**：闸在网关上，本地 Permit 毫无作用却让人以为开通了，所以 UI 根本不给，取而代之是**一键申请 + 理由**（待批 = `enabled=false` 的规则，批准即启用，不存在「批了没生效」）。观测按调用者在**服务端**过滤，不靠前端藏。顶栏「出口」与「管理对象」是**两个**控件——合成一个的话，打开远程网关的配置就会把自己的流量甩到另一个国家。
- **里程碑 17（✅ 主体）** ✅**跨平台**：`internal/paths` 收拢所有「文件放哪 / 有没有权限」，`internal/service` 补 systemd 与 Windows SCM，桌面壳一个壳三种提权（osascript / pkexec / UAC；**Linux 刻意不拿 sudo 兜底**——GUI 没终端可问密码，免密 sudo 机器上会不弹提示就提权）。回归：`make e2e-linux`（特权容器 pid1=真 systemd）、`make e2e-macos`（tart）。**Windows 未在真机验证**。（当时服务安装还会「问一句要不要拷个人数据」，里程碑 18 把这个交互删了——它跑在没有终端的授权框后面。）
- **里程碑 18（✅）** **一台机器一个网关**。用户级网关整个删除，入口收敛成 `sudo trust-proxy install` 一条命令：拷托管副本 → 注册服务 → 启动 → 开机自启 → 一次性收编旧 `~/.trust-proxy` → 建第一个 admin 并把 API key 交给 `SUDO_USER`。`env --json` 成为机器事实源（含 `action` 四态），桌面壳删掉自己拉网关的整条路径、改为只渲染。鉴权收敛：未认领的开放 admin **只对 loopback**（补掉一个真洞——一次性码只守 bootstrap，暴露的未认领网关谁先扫到谁是管理员）、`credentials.json` 带 `gateway_id` 回归、`/api/auth/ticket` 一次性票换 cookie、401 类型化。升级不再静默：`/api/health` 对 loopback 报 version/pid/managed，新 app 遇到旧 daemon 会给「Update」而不是贴上去装作没事。
  **这一轮 8 个缺陷是跑 e2e 跑出来的，读代码一个都没发现**：① 收编从未生效（种配置让目标目录「看起来已有数据」）② 被拒绝的 install 仍留下那份种子 ③ 非特权 `serve` 死在 `clash-secret: permission denied`（`MkdirAll` 对已存在目录成功，权限判断没触发）④ 重跑 install 被自己拦住，而 `--takeover` 救不了（服务托管的网关没有 pid 文件）⑤ `stopGatewayOn` 只等端口不等进程 ⑥ `auth login` 按 label 撤 key，连别人导出到脚本里的一起撤 ⑦ takeover 完全依赖 pid 文件，且**失败时先删了它**——单向棘轮，每重试一次少一条线索 ⑧ 发布包带 `configs/`，于是解压后 install 的种子来自 cwd。
  规矩：**改 `cmd/` 之后必须 `go test ./cmd/...`**（`go build`/`go vet` 不执行 `init()`，我靠 VM 才发现一个重复注册 flag 的 init panic）。CI 现在跑 vet/test/selftest/e2e-linux/cargo test/控制台，以前一个都不跑。
- **后续** DNS 查询级观测（TUN）、多节点聚合视图、**Segments**（按来源网段分层 split/strict 姿势,见 `docs/home-gateway-plan.md`）。

## 许可证
- 本项目整体 **GPLv3 开源**（链接/内嵌 GPLv3 的 sing-box + 官方 dashboard，含命名附加条款）。
- **公开分发二进制/桌面端（Tauri）**：分发物须遵守 GPLv3——随附对应源码、保留上游版权与 GPLv3 文本；不得用 sing-box 名号做宣传。
- 桌面端打包 sing-box（GPLv3）→ 整个分发物即 GPLv3，这是**已选定的路线**（非闭源）。
- （历史：早期设想「自用不分发→不触发分发义务、自研可闭源」；已改为 GPLv3 公开分发，该假设**作废**。仅当日后要**闭源**分发，才需进程隔离 / 商业授权。）
