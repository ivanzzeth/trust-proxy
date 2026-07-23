# trust-proxy 待办交接（handoff）

> 给新会话看的。当前 `main` 干净、可编译。每个任务:**build + 验收 + commit** 才算完成;
> 保持 i18n(新文案加 en/zh)、别把正交概念混层(见 memory `separate-orthogonal-concerns-by-layer`)、
> 优先用 sing-box 原生接口、密钥永不进仓库。测试起临时实例**用独立端口 + 结束用 PID kill**
> (`kill %1` 跨 Bash 调用无效,会残留孤儿进程;别动用户网关 pid)。

## 本会话已完成(勿重做)
- **A/B/#11 Rules 页统一 + 规则集内容查看 + 生效策略来源标注(✅)**:见下「~~A~~/~~B~~」条目。
- **Task C 自定义路由规则(✅)**:见下「~~C~~」条目——有序 store + 引擎 L4 + API + dashboard + node 自愈。
- **P0 分层 allow 闸重构 + no-proxy 路由层(✅)**:白名单=纯 ACL(允/拒),出口交给 routing。
  引擎按 L0 管理救援 / L1 安全地板(reject) / L2 Global 旁路 / **L3 ACL 闸**(一条 logical-or-invert `route→blocked`) / **L4 路由**(direct-bypass→direct、allow-proxy 集→proxy、兜底→proxy) 分层
  (`internal/gateway/gateway.go`:`injectAllow`+`injectProcessDeviceFloor`,拆自旧 `injectWhitelist`;`injectRuleSets` 只留描述符+block reject;`injectClashModeGlobal` 移到 `injectAllow` 前)。
  新 `internal/directlist`(no-proxy 域名/IP store,镜像 blacklist)+ `/api/directlist` CRUD + ACLs 页第三 tab「No-Proxy/免代理」+ i18n。
  内置私网段(RFC1918/loopback/CGNAT)自动直连(LAN 永不出境)。空允许集→无闸→兜底 blocked=全拒(fail-closed)。
  单测覆盖 8 条不变量 + sing-box schema 解析校验;端到端已验(白名单可达/未列拒/黑名单胜/no-proxy IP 直连可达/未列 IP 拒)。
- 黑白名单**通配符/前缀/后缀**匹配(glob→domain_regex)
- 专属 **logo**(盾+流量检查点)+ favicon
- **i18n 全站中英**(react-i18next;`src/i18n/pages/<ns>.ts` 每页模块 + `import.meta.glob` 合并;Settings 语言切换)
- `serve --daemon`、数据目录统一 **`~/.trust-proxy`**(cache.db/ts-state 也走 dataDir)
- pnpm 构建修复(`pnpm-workspace.yaml` 的 `allowBuilds: esbuild: true`)
- RuleSets **经代理下载**(有出口时 `download_detour=proxy`,穿 GFW)
- **A 后端**:`GET /api/rulesets/{tag}/rules?q=&offset=&limit=`(srs.Read(recover=true) 解码 .srs,搜索/分页;内存缓存 10m)
- **IA 重构(部分)**:ACLs 页(白名单Allow+黑名单Deny 两 tab)、Endpoints→**VPN** 改名、侧边栏分组(Monitor/Policy/Egress/System);`/whitelist`·`/blacklist` 重定向到 `/acls`

---

## ~~P0 —— 统一 allow 闸重构~~（✅ 已完成,见「本会话已完成」+ CLAUDE.md 分层顺序表）

分层引擎 + no-proxy 列表已落地并端到端验证。剩下的延伸(C / #10)如下。

---

## ~~C —— 自定义路由规则 CRUD~~（✅ 已完成）
- `internal/customrules`(有序 store,`data/customrules.json`):每条 `{match(domain/domain_suffix/keyword/regex/ip_cidr), action(direct|proxy|block|node)}` + 启用 + **排序**。`SingboxMatchKey` 映射到 sing-box matcher。
- 引擎:`injectAllow` L4 **最先**发射自定义规则(direct/proxy/blocked/`<node tag>`);direct/proxy/node 的 matcher 进 ACL 允许集(block 不进);**node self-heal**——tag 不在当前 outbound 成员集(`injectOutbounds` 现返回 memberTags)则跳过该规则,不 brick。
- API:`GET/POST/PATCH/DELETE /api/customrules` + `POST /api/customrules/{id}/move`(失败回滚)。dashboard `custom-rules.tsx`(有序表 + match/value/action + node 下拉[源 `proxies.proxy.all`] + 失效 badge + ↑↓ 排序 + 增删),Policy 侧边栏入口,i18n 中英。
- 单测:store(校验/幂等/排序/sanitize)+ gateway(允许集成员、L4 顺序、node self-heal、parseValidate);端到端已验(block 覆盖白名单、启停、死节点自愈、400 校验)。
- **剩余**:白名单域名的「直连/代理」快捷入口(其实=加一条自定义规则)可后续在白名单 UI 上加个便捷按钮。

## #10 —— Allow 包(一键应用的命名规则组)【后续】
- 白名单/自定义规则支持**命名分组(pack)**,一键启用/停用/应用整组;内置预设(China-direct、Google、Dev: github/npm、Apple)+ 用户自定义。构建在 C 之上(一个 pack = 一组带标签的 customrules/白名单条目)。

## ~~A 前端 + #11 Rules 页统一~~（✅ 已完成）
- 统一 **Rules 页**（`dashboard/src/pages/rules.tsx`，tab）：**Routing**(B 生效策略) / **Rule Sets**(现有 + A 点开看内容) / **Custom**(C)。`rulesets`/`custom-rules` 加 `embedded` 内嵌;`/rulesets`·`/custom-rules`→`/rules` 重定向;Policy 侧边栏合成单一 `/rules`。
- A：`api.rulesetRules(tag,q,offset,limit)` + Rule Sets tab 每行「查看」→ 内联面板（搜索防抖 + 分页 + entries）。**GFW 提示**：直连拉取失败时提示换 jsdelivr 镜像（后端仍 `directGet`；如需彻底解决再上 fetch-via-proxy）。

## ~~B —— Rules 页规则来源标注~~（✅ 已完成）
- `Manager.EffectiveRules()` 从各 store 推导**带 provenance 的生效规则列表**（按 L0..L4 + 来源 management/blacklist/rule-set:tag/process/device/global/acl-gate/no-proxy/private/custom/default-deny 标注），`GET /api/effective-rules`;Routing tab 分层渲染 + 彩色来源/动作 Badge。**防漂移测试**保证与真实 merged 配置层序一致。（非 Clash `/rules` 镜像;`/api/rules` 端点仍保留给 API 用户。）

## #5 —— TUN 权限 UX 友好化
- 非 root 点 TUN 别弹原始 `operation not permitted`,给友好提示 + 引导(sudo / setcap / 桌面端提权)。
- 确认 TUN→manual 切换永远安全(纯重建、无需 root、不武装死亡开关)、UI 不阻塞。
- 归入桌面端提权(#4)。

## #6 —— 移动端:客户端配置导出
- 导出可给 **SFA(Android)/ SFI(iOS)/ Clash Meta / Shadowrocket** 导入的配置/订阅:CN 直连 / 境外走自建出口。检测在出口/网关侧。**不做原生 App**(iOS NE 内存限制 + GPL 与 App Store 冲突)。附使用指引。

## #4 —— Tauri 桌面壳（大,最后）
- Tauri v2,把 `trust-proxy serve` 作为 **sidecar** 打包,壳启动即拉起、webview 指向 127.0.0.1:9096,数据 `~/.trust-proxy`。
- 目标平台:**Windows / macOS(仅 arm64)/ Linux**。
- TUN 需**透明提权**(用户别感知 sudo)。产出 GPLv3 安装包(.msi/.dmg/.AppImage)。
- sidecar 模型**不适用移动端**(见 #6)。

---

## 给用户的即时动作(非开发任务)
- **救 aliyun(分层后的正确姿势)**:白名单只管「允不允许」不再强制出境。要让 aliyun 走直连:① 在白名单放行 `aliyun.com`/`aliyuncs.com`/`alicdn.com`(或启用 geosite-cn allow-direct 批量放行),② 若挂了境外出口且想让它直连,把这些域名(或 IP)加进 **ACLs → 免代理(No-Proxy)** tab(私网/LAN 已自动直连,无需手动加)。不再需要「从白名单删掉」的旧绕法。
- **升级网关**:用户网关跑的是旧二进制,`git pull && make build` 重启才能拿到分层引擎 + no-proxy + 「规则集经代理下载」等修复。

## 许可证/安全红线(持续)
- 全项目 GPLv3,可公开分发;分发物随附源码+保留声明。
- 机场订阅凭据 / anytls 密码 / 服务器 IP **永不入库**(提交前 `git grep --cached` 扫)。
- `dashboard/dist`、`data/`、`~/.trust-proxy` 属运行时,gitignore。
