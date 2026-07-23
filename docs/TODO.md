# trust-proxy 待办交接（handoff）

> 给新会话看的。当前 `main` 干净、可编译。每个任务:**build + 验收 + commit** 才算完成;
> 保持 i18n(新文案加 en/zh)、别把正交概念混层(见 memory `separate-orthogonal-concerns-by-layer`)、
> 优先用 sing-box 原生接口、密钥永不进仓库。测试起临时实例**用独立端口 + 结束用 PID kill**
> (`kill %1` 跨 Bash 调用无效,会残留孤儿进程;别动用户网关 pid)。

## 本会话已完成(勿重做)
- 黑白名单**通配符/前缀/后缀**匹配(glob→domain_regex)
- 专属 **logo**(盾+流量检查点)+ favicon
- **i18n 全站中英**(react-i18next;`src/i18n/pages/<ns>.ts` 每页模块 + `import.meta.glob` 合并;Settings 语言切换)
- `serve --daemon`、数据目录统一 **`~/.trust-proxy`**(cache.db/ts-state 也走 dataDir)
- pnpm 构建修复(`pnpm-workspace.yaml` 的 `allowBuilds: esbuild: true`)
- RuleSets **经代理下载**(有出口时 `download_detour=proxy`,穿 GFW)
- **A 后端**:`GET /api/rulesets/{tag}/rules?q=&offset=&limit=`(srs.Read(recover=true) 解码 .srs,搜索/分页;内存缓存 10m)
- **IA 重构(部分)**:ACLs 页(白名单Allow+黑名单Deny 两 tab)、Endpoints→**VPN** 改名、侧边栏分组(Monitor/Policy/Egress/System);`/whitelist`·`/blacklist` 重定向到 `/acls`

---

## P0 —— 统一 allow 闸重构(分层修复,最优先)

**背景/为什么**:当前 `injectWhitelist` 把白名单**域名写死路由到 `proxy` 组**(IP→direct),把「允许」和「选出口」两层混一起 → 白名单的国内站(如 aliyun)被强制送去境外出口而打不开。用户要求严格分层:**白名单只管允不允许,出口是 routing 的事**。

**sing-box 约束(关键)**:扁平 route(first-match)里「允许」=「路由到某出口」是同一操作,没有"先允许再由后续规则选出口"。所以**不能**简单把白名单改成"不在名单就 block"的闸放在规则集前——那会**破坏规则集批量放行**(如 `geosite-cn allow-direct` 让所有 CN 域名放行+直连,不需逐个加白;naive 闸会把没单独加白的 CN 域名提前 block)。

**正确模型(要实现的)**:
1. **一个统一 allow 闸**(ACL 层):`route→block  一切 不属于 (白名单域名 ∪ 白名单IP ∪ allow-规则集命中) 的流量`。
   - 用 `route→"blocked"`(**不是 action:reject**),让被拦连接仍过 detector、保留 sniff 的 SNI、可一键加白(保住里程碑5)。
   - 域名用 `domain_suffix` + `domain_regex`(glob);与 IP、与 allow-规则集 tag 用 `{type:logical, mode:or, rules:[...], invert:true}` 组合。
   - **空白名单(且无 allow 规则集)→ 不生成闸 → 兜底保持 block = 全拒(fail-closed)**。
2. **Routing 层(纯出口)**:allow-规则集 → direct/proxy(只选出口);自定义规则(见 C);**兜底 catch-all 改成默认出口 `proxy`**(仅当有 allow 闸时;否则维持 block)。
3. 效果:aliyun 被允许(在白名单或 geosite-cn)→ 出口由 geosite-cn 判 **direct**;白名单不再碰出口;geosite 批量放行不破。

**实现要点**:allow 闸需**同时**拿到白名单 + allow-规则集 tag——现在 `injectWhitelist` 与 `injectRuleSets` 分离,要小改注入管线(把两者输入喂给同一个闸构建;注意注入顺序:blacklist/ruleset-block 在最前,闸在其后,routing 出口规则再后,catch-all 兜底)。

**回归测试(必须全过)**:
- 空白名单 → 全拒。
- 白名单域名 X → X 可达,且出口由规则/兜底决定(不写死 proxy)。
- geosite-cn(allow-direct)未单独加白的 CN 域名 → **放行 + 直连**。
- 白名单某域名 + geosite-cn direct → 该域名走直连(不再 proxy)。
- 黑名单优先于一切(仍 reject)。
- 被拦连接仍可见于连接页 + 一键加白。
- 挂境外出口时:境外站→proxy、国内站→direct 各就各位。

---

## C —— 自定义路由规则 CRUD（P0 的延伸,routing 层)
- 新 store `internal/customrules`(或并入现有):每条 `{matcher(domain/domain_suffix/keyword/regex/ip_cidr/wildcard), action(direct|proxy|block|指定节点tag)}`,可增删改**排序**。
- 注入到 routing 层(allow 闸之后、catch-all 之前);API CRUD + dashboard 编辑器。
- 白名单域名可选「直连/代理」= 其实就是"允许"+"一条自定义 routing 规则"的组合(别再在白名单里塞出口)。

## #10 —— Allow 包(一键应用的命名规则组)
- 白名单/allow 规则支持**命名分组**,一键启用/停用/应用整组;内置预设(China-direct、Google、Dev: github/npm、Apple)+ 用户自定义。并入 C 的分组能力。

## A 前端 + #11 Rules 页统一(IA 重构剩余部分)
- 新建统一 **Rules 页**(tab):**Routing**(B 来源标注)/ **Rule Sets**(现有 + A 详情:点开规则集→搜索/分页看内容,调 `GET /api/rulesets/{tag}/rules`)/ **Custom**(C)。
- 侧边栏 Policy 组现在还并列 `/rules` + `/rulesets`,统一后合成一个 `/rules`(tab),`/rulesets` 重定向。
- A 后端已就绪,只差前端详情视图。
- **GFW 注意**:A 的 `Decode` 目前 `directGet` 直连拉 .srs,国内 github 源会失败;需要时改成经网关代理拉取(fetch-via-proxy),或提示用 jsdelivr 镜像。

## B —— Rules 页规则来源标注
- 后端给出**带 provenance** 的生效规则列表:每条标出来源(whitelist / blacklist / rule-set:tag / mode(Global) / management / default-deny)。从我们的注入逻辑生成视图(而非 Clash 只读 `/rules` 镜像)。前端分组/标注。

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
- **救 aliyun**:把 `ecs.console.aliyun.com` 从白名单**删掉**(当前白名单域名→proxy 会强制出境),让 geosite-cn(allow-direct)接管→直连。控制台还需放行 `aliyun.com`/`aliyuncs.com`/`alicdn.com` 一组(或靠 geosite-cn)。
- **升级网关**:用户网关跑的是今天之前的旧二进制,`git pull && make build` 重启,才能拿到「规则集经代理下载」等修复(否则 geosite-cn 拉不下来=空规则集)。

## 许可证/安全红线(持续)
- 全项目 GPLv3,可公开分发;分发物随附源码+保留声明。
- 机场订阅凭据 / anytls 密码 / 服务器 IP **永不入库**(提交前 `git grep --cached` 扫)。
- `dashboard/dist`、`data/`、`~/.trust-proxy` 属运行时,gitignore。
