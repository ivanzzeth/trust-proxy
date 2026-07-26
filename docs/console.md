# 控制台（`dashboard/`，shadcn/ui + Tailwind + React 19）

浏览器只连 **`:9096` 单一 origin**，一切走 `/api/*`；连接/代理组/日志由后端代理 Clash API，**浏览器不碰 Clash secret**。
HashRouter，无需 SPA 服务端兜底。

- **Overview**：实时流量、连接数、告警计数、当前姿势/模式。
- **Connections**（一页三标签 **全部 / 活动 / 已关闭**）：活动连接来自 Clash API（可断开单条/全部）；已关闭来自持久化历史。每行带状态（活动 / 已放行 / **已拦截**）——**被拦的连接也可见**（兜底路由到 `block` 出站而非 `reject`，detector 因此仍能记录并拿到嗅到的 SNI）。每行**一键加白**：`+域名` / `+IP` / `+进程` / `+设备`（来源 IP），第一次被拦点一下就热重载放行；`+IP` 仅在目标确为 IP 时出现。
- **Detection**：检测阈值（beacon / DGA / exfil / 处置四组，改完即时进引擎）、隔离区（网关自行封禁的目的地，可放行）、DNS 查询级统计、JA4 指纹基线、主机侧完整性（路由劫持 / LocalNet 越界）。
- **Nodes（订阅/节点）**：三种添加方式 —— ① 订阅链接（可经代理抓取）② 手动填写（选协议出对应字段）③ 粘贴（share 链 / base64 / Clash YAML / sing-box JSON）。外加 **自建出口**对话框：网关一次生成服务端配置 + 配对客户端节点 + 部署脚本，可直接「添加为节点」。列表可**应用（热重载进 `proxy` 组）/ 刷新 / 删除**。
- **Profiles（配置档）**：把整套策略（Permit / Deny / 免代理 / 规则 / 规则集 / 分组 / DNS / 模式 + 当时启用的订阅）打包成命名快照，一键切换＝一次原子重建。页面常显**当前策略**的实时统计（即「保存」会抓下来的内容）；激活是**整份替换**，故有确认。
- **Policy**：Permit（可否出网）/ Route（走哪）/ Deny（硬拒绝）/ Subjects（进程·设备）四轴分开。进程放行一旦非空，**不在列表内的进程连接全部拒绝**——未知二进制即便去 Permit 过的目标也出不了网；设备放行是 `source_ip_cidr` 来源白名单（网关模式只放行已知设备）。增删**即时热重载**；非法条目（如把域名填进 IP）被拒绝且不落盘，已污染的存储在加载时自动清洗。
- **Rules**：三标签 —— **Routing**（从各 store 推导的 L0..L4 生效策略视图，带来源标注）/ **Rule Sets**（公开 `rule_set` 一键导入 + 点开看内容，每条选角色 deny / permit / route-direct / route-proxy / permit+route-*）/ **Custom**（有序策略规则 + 策略包：Claude/OpenAI/Cursor/China…）。
- **Proxies**：出站组（节点选择 + 延迟测速）、代理分组配置（Auto / 🌏 Overseas / 按国家 / 用户自定义组、排除地区）。
- **Endpoints / VPN**：WireGuard / Tailscale 出口——粘贴 wg-quick 配置或填 Tailscale auth key，启用后自动加入 `proxy` 组（与订阅节点并列）。secrets 服务端保存，不回浏览器。
- **DNS**：服务器（local/udp/tcp/tls/https/quic）+ 分流规则（domain_suffix / rule_set → server）+ strategy/final + fakeip/hosts，含预设。`detour: proxy` 让 DNS 走出口节点**防泄漏**；`direct_server` 是走 direct 的域名用的国内解析器（见 CLAUDE.md「DNS 跟随 Route」）。
- **History**：**持久化**的每条完成连接（`history.jsonl`，重启不丢）——总上下行、连接/拦截数、24h 趋势、top talkers、按 host 搜索明细。轮转后的旧代仍可翻阅。
- **Gateways（多网关）**：注册远程网关（探针）+ 健康状态 + 顶栏一键切换视图。大脑反代到各探针，token 服务端保存，浏览器单 origin 不碰 token。
- **Settings**：代理入站鉴权（mixed 账号密码，空=开放）+ TUN 高级选项（stack / mtu / strict_route / 按包名分流）。
- **Logs**：实时日志流（后端把 Clash WS 转 SSE）。

**顶栏常驻**：Posture（Strict ↔ Split）+ Routing（Rule ↔ Global）+ Capture（手动 / 系统代理 / TUN）+ 威胁自动阻断开关 + 实时流量 + 威胁情报计数 + 明暗主题 + 网关切换。

旧路径重定向：`/whitelist`·`/blacklist` → `/acls`，`/rulesets`·`/custom-rules` → `/rules`。

## 构建

```bash
make dashboard       # -> dashboard/dist（:9096 从磁盘 serve，适合开发）
make build-embed     # 把 dist 嵌进二进制（-tags embed_ui），发布单文件
make dashboard-test  # vitest（jsdom，对着 mock 的 /api 断言页面真的渲染出后端返回的东西）
cd dashboard && npx tsc --noEmit
```
