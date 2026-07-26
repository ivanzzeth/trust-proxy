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
| **1. 功能** | `internal/gateway`（注入/重建）、`internal/detect`、各 store（`internal/{whitelist,customrules,ruleset,dnscfg,…}`） | 该包单测 + **`make build && ./trust-proxy selftest`**（VM 里 `sudo` 跑覆盖 tun）。涉及安全语义的必须新增 selftest 场景，并**验证去掉修复后该场景会 FAIL**（测试得有牙齿） |
| **2. API** | `internal/api`（路由 + 入参校验 + **失败回滚**，别让一条坏数据 brick 网关） | handler 单测（`internal/api/*_test.go`）+ 对真实实例 curl 一遍；错误必须以 `{"error":…}` 透出，不能静默成功 |
| **3. SDK** | `pkg/client`（每个端点一个薄方法，wire 类型只放 `pkg/apitypes`，**不建第二套模型**）；底层 Clash 原语在 `pkg/clash` | `httptest` 假后端断言 method/path/body/token（`pkg/client/policy_test.go`）。**注意返回整份 store 文档的端点要解包** |
| **4. CLI** | `cmd/*.go`（cobra，走 SDK 而非直接拼 HTTP）；每个命令必须有 `--json`，共享 `--api-addr`/`--api-token` | VM 里对真实网关跑通，且**每个写操作用另一个命令读回来**验证（no-proxy 不能顺带授予 Permit 这类轴隔离要显式断言）；危险开关要确认提示 + `-y` |
| **5. WebUI** | `dashboard/`（页面 + `src/lib/api.ts` 类型 + `src/i18n/pages/*.ts` 的 en/zh 双语） | `npx tsc --noEmit` 通过 + 页面实操；只连 `:9096` 单一 origin，浏览器不碰 secret |

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
     :17070             │ sing-box 核心 (route / sniff / 连接跟踪)          │──direct/代理──▶ 出网
                        │      │                         ▲                  │
                        │      │ AppendTracker(未来)     │ service/api      │
                        │      ▼                         │ (Connect/proto)  │
                        │  检测引擎(未来)           官方 React dashboard    │◀── 浏览器 :9095/dashboard/
                        │  信誉/beacon/外泄/断连     (webui/, 我们自维护)   │
                        └─────────────────────────────────────────────────┘
```

三层职责：

| 层 | 现状 | 实现 |
|---|---|---|
| **数据面** 代理/路由/分流/连接跟踪 | ✅ sing-box 原生 | `configs/config.json` 的 route 规则；**白名单默认拒绝**（allow-list 放行 + 末尾 `reject` 兜底）；`sniff` 取 SNI |
| **控制面/UI** | ✅ 里程碑 0 | 官方 dashboard（`webui/`），走 sing-box 内置 `service/api`（Connect/protobuf daemon，**非 Clash REST**） |
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
- **我们自建的控制台 `dashboard/`（shadcn/ui + Tailwind v4 + React 19 + Vite）** 是唯一 UI，由后端 `internal/api`（:9096）从 `dashboard/dist` serve，`make dashboard` 构建。**浏览器只连 :9096 单一 origin**，一切走 `/api/*`；连接/代理组/日志都由后端**代理 Clash API**（浏览器不碰 Clash secret）。HashRouter，无需 SPA 服务端兜底。
  - 页面：Overview / Connections（全部·活动·已关闭 + 一键加白）/ Nodes / Profiles / **Policy**（Permit / Route / Deny / Subjects）/ **Rules**（Routing 生效视图 + Rule Sets + Custom/策略包）/ Proxies / Endpoints/VPN / Settings / DNS / History / Fleet / Logs。（`/whitelist`·`/blacklist`→`/acls`，`/rulesets`·`/custom-rules`→`/rules` 重定向。）
  - **（历史）曾 vendored Yacd 作底座（`console/`），里程碑 5 后整体换成自研 shadcn 应用并删除 Yacd**——不再有前端 upstream 同步负担。
- **官方 dashboard（`webui/`）** 仍可选保留，只做 sing-box `service/api` :9095 的运行时监控；平时用不到。
- **go:embed 单二进制（✅）**：默认构建从磁盘 serve `dashboard/dist`（开发）；`make build-embed`（或 `-tags embed_ui`，见 `embed_ui.go`）把前端嵌进二进制，release 单文件自带 UI（`internal/api` 的 `consoleHandler` 用 `fs.FS`：embed 优先、否则 `os.DirFS(--console)`）。

**为什么单进程**：深度检测（挂 tracker、镜像连接、自定义 outbound）必须和 sing-box 同进程；
纯元数据检测才可跨机。将来若要「一个控制台管多节点」，用「探针(数据面)+大脑(分析/UI)」分离，探针仍是本二进制。

### 单一二进制 + CLI/SDK 分层
一个二进制既是后端也是 CLI 客户端，靠子命令区分：
- `trust-proxy serve` — 跑网关（sing-box 数据面 + detection + 我们的后端 `/api`）。
- 其余子命令 = **CLI 客户端**，经 **Go SDK** 调运行中的后端。

**SDK 两层**（回应「先封装标准接口为底层原语，上层再易用封装」）：
- `pkg/clash` — **底层原语**：直连标准 **Clash API**（`/connections`、`DELETE /connections/{id}`、`/version`…）。通用、可复用于任何 sing-box/mihomo/clash。
- `pkg/client` — **上层易用**：调我们自己的 `/api`（订阅等），并**组合** `pkg/clash`（`client.Clash` 暴露原语，`client.Connections()/Kill()` 是便捷封装）。
- `pkg/apitypes` — 共享 wire 类型（无内部依赖，避免 import 环）。

**CLI 覆盖全部 API**（控制台能做的，命令行都能做；每个子命令都有 `--json` 供脚本消费，`--api-addr`/`--api-token` 指向本机或探针）：
`status` | `acl ls|add|rm <permit|deny|no-proxy>` | `rules ls`(生效视图) `rules custom|packs|sets …` | `dns get|set`（`--direct-server` 等单项 patch，`-f` 整档替换）| `mode get|set|confirm`（`--guard` 死亡开关）| `routing get|set`(Rule/Global) | `posture get|set` | `final get|set` | `profile ls|save|activate|rm` | `proxies ls|select|delay` | `groups get|set` | `endpoints ls|add|toggle|rm` | `tun get|set` | `inbound get|set` | `autoblock on|off` | `detections ls|stats` | `history ls|stats` | `node ls|add|rm`(fleet) | `sub add|import|ls|apply|rm|refresh` | `conn ls|kill`(底层 Clash 原语→:9090)。
**坑**：`/api/customrules` 与 `/api/rulesets` 返回的是**整份 store 文档**（`{"rules":[…]}` / `{"sets":[…]}`），不是裸数组——SDK 里 `customRulesDoc`/`ruleSetsDoc` 负责解包（`pkg/client/policy_test.go` 有回归）。

### 关键文件 / 目录
```
main.go                    thin: cmd.Execute()
cmd/{root,serve,sub,conn}.go  cobra 命令
internal/gateway/          box 引导 + detector + 热重载注入(outbounds/mode/whitelist/rule_set/no-proxy/customrules) + ApplyProfile + `Manager.EffectiveRules()`(从各 store 推导 L0..L4 生效策略视图,`/api/effective-rules`;`memberTags` 单一来源给 node tag 命名+自愈校验)
internal/detect/           检测引擎（事件环形缓冲 + 字节计数 + 威胁情报匹配 + 持久化恢复）
internal/threatfeed/       威胁情报 feed 加载器（abuse.ch，定时刷新 → engine.SetFeedThreats）
internal/ruleset/          规则集存储 + 公开规则库 catalog（JSON 存 data/rulesets.json）
internal/profile/          配置档存储（快照订阅/白名单/规则集/模式，data/profiles.json）
internal/dnscfg/           DNS 解析策略存储（servers/rules/strategy + fakeip/hosts + **direct_server/disable_direct_split** → 注入 sing-box dns 块，data/dns.json）
internal/blacklist/        出网黑名单（域名/关键字/正则/IP → reject，injectBlacklist 注入在 sniff 之后、白名单之前）
internal/directlist/       no-proxy 旁路（域名/IP → direct，**仅 L4 Route**，不开闸；私网段引擎内置）
internal/proxygroups/      代理分组（Config{AutoCountry,ExcludeCountries,Groups}）+ 国家解析(country.go：旗emoji/中英/国码→ISO)；injectOutbounds 据此建 Auto(urltest全部)+**🌏 Overseas 共享组**(urltest,成员=国家∉ExcludeCountries 的节点;**仅当排除真的去掉≥1节点才建**,否则 Auto 已安全、指向它的规则 self-heal 回 Auto)+按国家 urltest 组+用户组(select/urltest,filter country/regex/manual)，proxy 改 selector(default Auto)。**Overseas 组**是「地区受限服务 failover」的载体:Anthropic/OpenAI 拒 HK/CN,geofenced 包(Claude/OpenAI/Cursor)走 Overseas→在允许地区间自动切、绝不落被封地区。ExcludeCountries 默认 HK/MO/CN(`DefaultExcludeCountries`,旧 store 加载时一次性迁移;nil=未设→填默认、非nil空=不排除),Proxies 页可改。sing-box 只有 selector/urltest,无 load-balance
internal/policymigrate/    Permit⊥Route 一次性迁移（allow-*→permit+route-*；directlist 拷入 whitelist；profiles v2）
internal/customrules/      有序策略规则（Permit 与/或 Egress 正交；L4 有序；node self-heal）+ **策略包**（`presets.go`：Claude/OpenAI/Cursor/…；**China (wide)=permit** + **China-direct=route-direct** 拆开；共享 tag 时 Merge/Subtract；Overseas 给地区受限服务）
internal/inbound/          入站鉴权（mixed users，applyMode 注入）
internal/tuncfg/           TUN 高级选项（stack/mtu/strict_route/exclude·include_package，applyMode 用）
internal/endpoints/        WireGuard/Tailscale 出口（wg-quick 解析；injectEndpoints 注入 endpoints[] + 标签加入 proxy 组）
internal/history/          每条完成连接的持久化历史（append JSONL + 聚合，detect.SetOnFinalize 喂）；**读路径按需读**（`read.go`：无过滤时只倒读活动文件尾部、total 走增量行数缓存；有过滤时先对原始行做 `bytes.Contains` 预筛、只解析候选——控制台每 5s 轮询一次，旧实现每次全量解析 45MB≈302ms，现在同规模 310µs）；轮转/保留交给 **lumberjack**（`--history-max-size/-keep/-max-age/-compress`），已轮转的代仍可在 History 页翻阅（`rotatedFiles()` glob + 透明解 gz；压缩是异步的，同一代会短暂出现 `.jsonl` 与 `.jsonl.gz`，故按代去重）
internal/logging/          日志栈：**zerolog**(编码) → **diode**(无锁 ring,不阻塞写者) → **lumberjack**(轮转/保留/gzip)；daemon 下把 fd 1/2 重定向进同一个 ring 以收走 sing-box 自己的行
internal/nodes/            多节点注册表（大脑侧，data/nodes.json；反代 /api/nodes/{id}/* → 各探针 /api，注入 token）
internal/api/              我们自己的后端 /api（stdlib mux；订阅/白名单/规则集/配置档 CRUD + 模式/状态/自动阻断 + 代理 Clash connections/proxies/logs + serve dashboard）
dashboard/                 我们自建的控制台（shadcn/ui + Tailwind v4 + React19 + Vite，走 /api 单一 origin）
internal/subscription/     订阅 抓取/解析(base64+share链)/JSON 存储（借鉴 s-ui）
pkg/clash/                 底层 SDK：标准 Clash API 客户端
pkg/client/                上层 SDK：/api + 组合 clash
pkg/apitypes/              共享 wire 类型
configs/config.json        sing-box 配置：白名单默认拒绝 + clash_api + service/api(+dashboard)
third_party/sing-box       【我们的 fork 子模块】`ivanzzeth/sing-box` 分支 `trust-proxy`，replace 进本模块；上游 SagerNet 为 `upstream`
webui/                     【上游 vendored 副本】官方 dashboard
data/                      运行时数据（subscriptions.json 等，gitignore）
```

### 数据面能力：现成 vs 自研
- **现成（配置即得）**：按 domain/geoip/ip/port/进程/rule-set/逻辑规则分流；`reject`/`block` 阻断；主动断连；
  连接级遥测（上下行字节、SNI、进程、命中规则、出站链）。
- **自研（检测大脑）**：异常判定（C2 信誉、beaconing、异常上行、DGA、DNS 隧道）、自动处置闭环、
  流量镜像给 DPI（自定义 outbound 包 `net.Conn` + TeeReader）、DLP、限速、告警/审计/UI。

---

## 从上游同步代码

有**两个**独立上游，同步方式不同。

### 1. sing-box（`third_party/sing-box`）— 我们的 fork 子模块

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
go mod tidy && make build
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

### 2. 官方 dashboard（`webui/`）— vendored 副本，半手动同步

我们**克隆后删了它的 `.git`**，把源码并入本仓自行维护（因为要往里加安全检测视图）。
因此它不是子模块，同步需要「拉上游 → 合并进 `webui/`，保留我们的改动」。

**推荐：git subtree（一次性接上，之后可 pull）**
```bash
# 一次性：登记上游为远端
git remote add dashboard-upstream https://github.com/SagerNet/sing-box-dashboard

# 之后每次同步（--squash 把上游历史压成一个提交并入 webui/）
git subtree pull --prefix=webui dashboard-upstream main --squash
# 解决与我们本地改动的冲突后：
make webui && make run                     # 重新 generate+build 验证
```

**备选：手动 diff（无 git plumbing，适合改动很小时）**
```bash
git clone --depth 1 https://github.com/SagerNet/sing-box-dashboard /tmp/sbd
diff -ru --exclude=.git --exclude=node_modules --exclude=dist --exclude=src/gen webui /tmp/sbd
# 逐项把上游变更并进 webui/，保留我们自加的安全视图，然后 make webui 验证
```

同步 dashboard 后务必重跑构建链（它有代码生成步骤）：
```bash
git clone --depth 1 https://github.com/mbadolato/iTerm2-Color-Schemes \
    webui/vendor/iterm2-color-schemes && rm -rf webui/vendor/iterm2-color-schemes/.git   # 若缺
cd webui && corepack pnpm install --frozen-lockfile && corepack pnpm run generate && corepack pnpm run build
```
- 用 **pnpm**（`packageManager: pnpm@11.13.0`，`corepack` 自动取版本），不是 npm。
- **build 前必须 `generate`**：`buf generate` 把 `proto/daemon/started_service.proto` 生成到 `src/gen`，App 直接 import。
- 我们改造 dashboard 时，尽量**新增文件/视图**而非改上游文件，降低未来 subtree 合并冲突。

---

## 构建 / 运行 / 验证

```bash
make deps        # 首次：git submodule update --init --recursive（拉 sing-box）
make build       # 编译 -> ./trust-proxy（TAGS="with_clash_api ..." 可选）
make run         # 用 configs/config.json 启动
make webui       # 构建官方 dashboard -> webui/dist（pnpm install→generate→build）
```

**端到端自测（`cmd/selftest.go`，`trust-proxy selftest`，hidden 子命令）**：**离线、确定性、可扔进 VM 跑**的核心引擎 e2e。自起两个本地「origin」（direct-origin 返回 `direct` / node-origin 返回 `node`）+ 一个 http CONNECT「node」上游，用**真实 `gateway.Manager`** 跑遍：默认拒绝拦截 / 白名单→node / no-proxy→direct / 黑名单胜 / 自定义规则 direct·proxy·block·node / system 模式；`sudo trust-proxy selftest` 额外覆盖 tun（loopback 不被 tun 捕获，故 tun 分支只断言 box 能在 tun 模式起来）。任一场景失败则非零退出。**改引擎后务必 `make build && ./trust-proxy selftest`**（VM 里 `sudo` 跑覆盖全部）。

**数据目录**：`serve` 默认把所有运行时数据放 **`~/.trust-proxy`**（`--data` 可覆盖；`~` 会展开）。含 subscriptions/whitelist/blacklist/events/history + **`cache.db`（clash mode/urltest/rule_set 缓存）** + `ts-<tag>`（Tailscale 状态）+ `clash-secret`。注意 `cache.db`/`ts-*` 的路径由 `gateway.Manager.dataDir` 注入（不再是 cwd 相对的 `data/`）。**旧部署迁移**：`mv ./data/* ~/.trust-proxy/` 或显式 `--data ./data`。
**后台守护**：`serve --daemon`（`-d`）re-exec 脱离终端（`daemonize`，`TP_DAEMON=1` 标记子进程），`--log`/`--pid` 默认 `<data>/serve.{log,pid}`；停止 `trust-proxy proxy stop --pid <data>/serve.pid`（`proxy stop` 通用杀 pid 文件）。同目录勿并跑两实例（`cache.db` 单写锁）。

**日志（`internal/logging`）**：`zerolog` → `diode` → `lumberjack`，全部用现成库，不手搓。轮转参数：`--log-max-size`(MB,默认 32)、`--log-keep`(默认 3)、`--log-max-age`(天,0=只按个数)、`--log-compress`(默认开)；`--log-max-size 0` 关闭轮转。
**为什么中间要有 ring**：sing-box 的 logger 是**在连接协程里同步 `writer.Write()`**（`log/observable.go`），info 级别每条连接/每个 DNS 应答一行——直接落盘等于每个连接付一次磁盘写，轮转（rename+gzip）还会卡转发。diode 把它变成无锁 ring push（实测 1889 ns/op → 203 ns/op，18 并发），ring 满了**丢日志并报告条数**，绝不对流量施加背压。
**为什么要重定向 fd 1/2**：sing-box 不给注入 writer（只有附加式 `PlatformLogWriter`，停不掉它对 stderr 的同步写），所以 daemon 子进程把 fd 1/2 换成 pipe（热路径只剩一次内核 memcpy）再汇入 ring。前台运行不接管 stdio——终端本身就是日志。

验证（不影响本机 Surge：无 TUN、不改系统代理、端口错开）：
```bash
curl -x socks5h://127.0.0.1:17070 https://api.ipify.org          # 代理出网
curl -x socks5h://127.0.0.1:17070 https://ads.doubleclick.net    # 命中黑名单 -> 连接失败(reject)
curl -x socks5h://127.0.0.1:17070 https://example.com            # 正常 -> 200
# 浏览器打开 http://127.0.0.1:9095/  （跳 /dashboard/）
```

| 服务 | 地址 |
|---|---|
| 代理入站 (mixed socks/http) | `127.0.0.1:17070` |
| API / dashboard | `127.0.0.1:9095`（UI 在 `/dashboard/`） |

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
- dashboard：pnpm、必须先 generate、有 vendor 子模块、UI 路径 `/dashboard/`。
- 可再生目录已 gitignore：`webui/{dist,node_modules,src/gen,vendor/iterm2-color-schemes}`。

## 作为代理服务器 / TUN 网关运行
同一个二进制三种角色：
- **客户端网关**：`trust-proxy serve`（mixed 入站 :17070 + 检测 + 白名单 + dashboard/api :9096）。
- **代理服务端（出口节点）**：`trust-proxy proxy run -c server.json`；一键生成：`trust-proxy proxy gen --type <ss|vless-reality|vless|vmess|trojan|anytls|hysteria2|tuic> --server <ip> --port <p>` → 输出服务端配置 + 客户端节点（Clash dict，可直接粘进 console）。TLS 协议自动内联自签证书（客户端 skip-cert-verify），vless-reality 免证书自动生成密钥对。
- **TUN 全流量网关**：`sudo trust-proxy serve -c configs/config.tun.json`（`tun` 入站 + `auto_route` 网络层接管**所有**出入网流量——木马的裸 socket 也逃不掉）。需 **root**，且与其他 TUN 工具（Surge 增强模式等）互斥，用于**专用网关机/软路由**。检测与白名单逻辑不变（同一 route）。构建需 `with_gvisor`（已在默认 TAGS）。
- **里程碑 0（✅）** 全栈跑通：Go 嵌入 sing-box + 代理 + 官方监控 UI。
- **里程碑 1（✅）** 白名单默认拒绝 + `AppendTracker` 检测器 + Clash API + 单一二进制 CLI/SDK 分层 + 订阅管理 + 订阅 apply + ✅**自动处置闭环**（`--auto-block`：威胁命中 → detector 直接断连，`internal/gateway/detector.go`）。
- **里程碑 2（✅ 主体）** 自建 React 控制台 + 单一 origin + 订阅/节点管理 + 实时连接 + ✅白名单 UI + ✅检测/告警页 + ✅规则集/配置档页 + ✅侧边栏模式切换。**待做**：go:embed 单二进制。
- **里程碑 3（✅ 主体）** 检测引擎（审计 + 字节计数 + 威胁情报命中 + 大上传外泄告警）+ 告警页；代理服务端一键部署（8 协议）；TUN 全流量网关；✅**威胁情报 feed 自动加载**（abuse.ch Feodo，`internal/threatfeed`，定时替换）；✅**事件持久化**（`data/events.json` 快照，重启恢复）；✅**运行时模式切换**（manual/system/tun，`gateway.applyMode`，失败回滚）。
- **里程碑 4（✅ 主体）** ✅**规则集一键导入**（公开 `rule_set` catalog + 按 URL；block/allow-direct/allow-proxy 角色注入，`gateway.injectRuleSets` + `internal/ruleset`）；✅**配置档（Profiles）一键切换**（`internal/profile` + `gateway.ApplyProfile` 单次原子重建）；✅**按进程放行**（白名单加 `Processes` 维度 → `injectWhitelist` 生成 `process_name/process_path` + `invert:true` 拒绝规则，未知进程连接直接拒；已实测 macOS loopback 能解析进程）；✅**按设备放行**（`Devices` 维度 → `source_ip_cidr` + `invert:true`，网关模式只放行已知来源设备）；✅白名单**输入校验 + 自愈**（非法 ip_cidr 拒绝不落盘、`SetWhitelist` 失败回滚保活、加载时 `sanitize()` 丢弃非法条目——防止一条坏数据 brick 网关）。
- **告警信噪比（✅）** 真机跑一天 1137 条告警里 1082 条是 beacon 噪声（GCM 推送/VSCode 更新/滴答清单/B站 API 这类正常心跳），根因两条：① `beaconReAlert=10min` **比它要检测的周期还短**——10 分钟一次的轮询于是每轮报一次，单主机一天 144 条；现在冷却期按实测周期缩放（`max(配置值, 36×interval)`）。② beacon/DGA 告警**完全不过 `isTrusted`**（`isTrusted` 原先只在 exfil 自动封禁处调用），于是你自己 Permit 过的 anthropic/cursor/googlevideo 天天报「可能外泄/DGA」。现在启发式告警一律过 Permit 闸，**威胁情报命中不受影响**（被许可的域名上了 abuse.ch 名单恰恰最该报）。注意 `trustedDest` 是调用方回调（会查 permit 缓存并自带锁），**必须在 `e.mu` 之外求值**——放进锁里会让每条连接串行等这次查找，还可能锁环。回归见 `internal/detect/noise_test.go`。
- **里程碑 5（🟡）** ✅**beaconing 检测**（同目标周期性回连、区间变异系数低 → 疑似 C2 心跳，`detect.recordBeacon`；启发式=仅告警不自动断，用 `Event.Block` 区分高置信威胁情报命中）；✅**连接页与事件页合并**（控制台单页三标签 全部/活动/已关闭 → `/connections`）；✅**被拦连接可见 + 一键加白**（兜底改 route→`block` 出站，detector 记录被拦连接 + SNI 域名；每行 `+域名/+IP/+进程/+设备` 直接 POST `/api/whitelist` 热重载放行）。**说明**：Clash API 只有活动连接（无 closed 端点），历史来自我们的检测事件——这是「看不见连接」的真因，非 bug。
- **里程碑 6（✅ 主体）** ✅**控制台整体换 shadcn/ui**（`dashboard/`：精致 SaaS 仪表盘，Overview/Connections/Nodes/Profiles/Whitelist/Rule Sets/Proxies/Logs，全部走 `/api` 单一 origin）；✅**Clash API 重做**（`pkg/clash` + `internal/api` 后端代理 `/proxies`、select、delay、`/logs`(WS→SSE)）；✅**删除 vendored Yacd（`console/`）**；✅**go:embed 单二进制**（`-tags embed_ui` 把 `dashboard/dist` 嵌入，release 二进制单文件自带 UI；默认构建仍从磁盘 serve 便于开发）。
- **里程碑 7（✅ 主体）** ✅**DNS 服务器/规则配置**（`internal/dnscfg` + `gateway.injectDNS`：typed servers local/udp/tcp/tls/https/quic + 分流 rules + strategy/final；`detour:proxy` 让 DNS 走出口节点防泄漏；校验 + `SetDNS` 失败回滚；DNS 页含预设）。这是 **DNS 隧道/DGA 检测**的前提（后续接观测：高熵子域名/异常 TXT/查询速率）。
- **里程碑 8（✅ 主体）** ✅**DGA / DNS 隧道检测**（`detect.analyzeDomain`：SLD 香农熵+数字/元音比→DGA C2；长高熵子域名标签→隧道；单父域 distinct 子域名计数→隧道/fast-flux。启发式=仅告警不自动断）。**坑**：proxy/socks 模式下 sing-box 直接按域名拨号（`outbound connection to <domain>`），**不经 DNS 路由**，故无 `lookup succeed` 日志——检测跑在 tracker 拿到的**连接域名**上（全模式可用）；基于日志观测 DNS 查询仅 TUN/hijack-dns 模式可行（后续再上）。
- **里程碑 9（✅）** ✅**per-connection 流量历史持久化**（`internal/history`：detect finalize sink → append `data/history.jsonl` + 内存聚合 top talkers/24h 趋势，重启从 JSONL 重建；`/api/history{,/stats}` + History 页）。
- **里程碑 10（✅ 主体）** ✅**多节点管理（探针+大脑）**：每个 `serve` 即探针（`--api-token` 给 `/api/*` 加 bearer 鉴权，`--api-addr 0.0.0.0` 暴露）；大脑 `internal/nodes` 注册表 + `internal/api` 反向代理 `/api/nodes/{id}/{rest...}`（注入各探针 token，SSE 透传）；控制台 Fleet 页 + 顶栏 NodeSwitcher（切换后 `queryClient.clear()` 全刷）。浏览器仍单 origin、不碰 token。
- **里程碑 11（✅）** sing-box 功能对接批量补齐（workflow 顺序实现，各自 build+test 通过才 commit）：✅Clash 规则只读查看（`/api/rules`）、✅**入站鉴权**（mixed users + Settings 页）、✅**DNS fakeip/hosts**、✅**TUN 高级选项**、✅**出网黑名单**（reject 优先于白名单）。（`clash_mode` 当时故意跳过——「Global/Direct 绕过默认拒绝」需专门设计；**已于里程碑 14 安全落地**，见下。）
- **里程碑 12（✅ 主体）** ✅**WireGuard / Tailscale 出口端点**（`internal/endpoints` + `gateway.injectEndpoints`：wg-quick 粘贴解析、注入 sing-box `endpoints[]`、标签加入 `proxy` 组;secrets 服务端保存不回浏览器)。构建默认加 `with_wireguard with_tailscale`(二进制 ~75M,Tailscale 拉大依赖);已实测 WG 端点解析+注入+入组、box 接受配置。
- **里程碑 13（✅）** ✅**远程防板砖**：管理端口豁免(`injectManagement`,`--management-ports`,API 口自动加)+ 模式切换死亡开关(`SetModeGuarded`/`ConfirmMode`/`PendingRevert`,`/api/mode` guard_seconds + `/api/mode/confirm`,控制台倒计时横幅,默认 60s)。
- **里程碑 14（✅）** ✅**路由模式 Rule↔Global 开关**（`gateway.injectClashModeGlobal`：注入 `clash_mode:"Global"` 路由规则,位于**安全 floor 之下、默认拒绝兜底之上**——Global 时默认拒绝关闭、未列入流量走 `proxy` 组,黑名单/威胁/进程·设备闸仍生效;Rule 时该规则不匹配、默认拒绝照旧。sing-box 按 `EqualFold` 大小写不敏感匹配,并从规则里的 clash_mode 值自动生成 mode list）。**热切换不重建**（Clash `PATCH /configs`）;`default_mode=Rule` + `experimental.cache_file` 持久化选择;`/api/clash-mode` GET/PUT 只放行 **Rule/Global**（**拒 Direct** 防全直连泄漏,`internal/api/clashmode.go`）;`pkg/clash` 加 `Mode()/SetMode()`;控制台顶栏 Routing 分段控件 + Global 琥珀警告横幅。曾在里程碑 11「故意跳过」,现按「安全 floor 常在」原则安全落地。**注意**:cache_file 现恒开(为持久化模式),同目录勿并跑两实例(bolt 单写锁)。
- **后续** DNS 查询级观测（TUN）、多节点聚合视图、**Segments**（按来源网段分层 split/strict 姿势,见 `docs/home-gateway-plan.md`）。

## 许可证
- 本项目整体 **GPLv3 开源**（链接/内嵌 GPLv3 的 sing-box + 官方 dashboard，含命名附加条款）。
- **公开分发二进制/桌面端（Tauri）**：分发物须遵守 GPLv3——随附对应源码、保留上游版权与 GPLv3 文本；不得用 sing-box 名号做宣传。
- 桌面端打包 sing-box（GPLv3）→ 整个分发物即 GPLv3，这是**已选定的路线**（非闭源）。
- （历史：早期设想「自用不分发→不触发分发义务、自研可闭源」；已改为 GPLv3 公开分发，该假设**作废**。仅当日后要**闭源**分发，才需进程隔离 / 商业授权。）
