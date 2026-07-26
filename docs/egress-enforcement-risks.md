# 出口管控：待决策的「强制」类改造（**暂缓，先只观测**）

> 状态：**不做**。本文记录调研结论、我们的真实暴露面、以及真要做时**必须先就位**的防板砖脚手架。
> 观测那一半已经上线（见文末「已落地」），先跑一段时间攒真实数据，再据此设计强制策略。

## 为什么单独拎出来

这几项的共同点是**会改动系统状态**。它们的失败模式不是「安全性降低」，而是
**整机断网、甚至连不上这台机器**——kill switch 按设计就是要让机器断网，这正是它危险的地方。
其余观测类改动最坏只是多几条误报，两者不该按同一个标准推进。

| 类别 | 代码出 bug 的后果 |
|---|---|
| 观测（已上线） | 误报几条告警 |
| **pf kill switch** | 全机断网，且**规则在我们进程死后依然生效** |
| **收窄 LAN 旁路** | 打印机/NAS/局域网 SSH 不通；极端情况把网关和本地 DNS 一起挡了 = 断网 |

---

## 风险 1：没有 kill switch，进程一死即全量放行

**现状**：TUN 模式下 `pkill trust-proxy` → utun 消失、路由回落 → 所有流量直接出去，
无策略、无检测。崩溃、OOM、升级重启都是这个窗口。项目的核心承诺是「出网默认拒绝」，
而这个窗口里它不成立。

**业界做法**：把开关放进**系统防火墙**而不是应用——`block drop all` + 只放行 utun 与节点 IP 的
pf 规则，进程死了规则还在（[vpn-kill-switch/killswitch](https://github.com/vpn-kill-switch/killswitch)、
[PF macOS & BSD](https://vpn-kill-switch.com/post/pf/)）。

**难点**：这与「进程死了要能恢复」直接冲突——一个能自动消失的 kill switch 不是 kill switch，
一个不会消失的 kill switch 能把人锁在门外。解法只能是**显式的、带多重逃生口的开关**（见下方脚手架）。

## 风险 2：TunnelVision（CVE-2024-3661）目前只能看不能防

**现状**：恶意 DHCP 用 option 121 下发比我们的 split default（1/8、2/7…）更具体的路由，
流量绕过 TUN 明文出去。已实现**监控**（`internal/netwatch`，VM 实测能报出注入的 `203.0.113.0/24`），
但没有任何阻断。

**可选强制手段**：pf 层面只放行 utun 出站（与风险 1 同一套机制）；Linux 侧可用 netns/fwmark
把出口绑死在隧道上（[Leviathan 原始报告](https://www.leviathansecurity.com/blog/tunnelvision)、
[Zscaler 分析](https://www.zscaler.com/blogs/security-research/cve-2024-3661-k-tunnelvision-exposes-vpn-bypass-vulnerability)）。

## 风险 3：LAN 旁路无条件覆盖 RFC1918 + CGNAT（TunnelCrack LocalNet）

**现状**：`internal/gateway/gateway.go` 的 `privateCIDRs` 同时进了 **Permit 允许集**和 **direct 路由**。
恶意网络只要声称某段是「本地」，流量就合法地走到隧道外并**绕过 Permit 闸**
（[TunnelCrack](https://tunnelcrack.mathyvanhoef.com/)、[USENIX 论文](https://papers.mathyvanhoef.com/usenix2023-tunnelcrack.pdf)）。
清单里含 `100.64/10`（CGNAT），恶意热点拿它当「本地」再合适不过。已实现**告警**（kind=localnet）。

**强制手段**：把旁路收窄到**当前接口真实的本地子网**（`netwatch.Snapshot().LocalNets` 已经能给出）。
**必须保留的逃生口**：无论怎么收窄，都要强制保留**当前默认网关**和**正在使用的 DNS 服务器**可达，
否则在只有局域网的环境里直接断网。建议默认保持现状、收窄作为 opt-in。

## 风险 4：ECH 让基于域名的 Permit 闸失去输入（可缓解，但会改行为）

**现状**：[RFC 9849](https://datatracker.ietf.org/doc/html/draft-campling-ech-deployment-considerations-12)
已于 2026-03 正式化，SNI 被加密后我们嗅到的是 cover 域名。已实现**观测**（ECH 配置走 HTTPS/SVCB
记录下发，我们拥有解析链路所以能数出「策略面有多少正在变得不透明」），以及不依赖 SNI 的
**JA4 指纹**。

**可选强制手段**：在 DNS 应答里**剥掉 HTTPS/SVCB 记录的 `ech` 参数**，让客户端退回明文 SNI
（企业侧通行做法）。不改系统状态，但**改行为**：某些站点会丢 HTTP/3 或 SVCB 优化，
所以仍应是 opt-in + 可回滚（`SetDNS` 已有失败回滚）。

## 风险 5：客户端自带 DoH 绕过（同上，缓解手段会改行为）

**现状**：已实现**检测**（kind=dns-bypass）。

**可选强制手段**：应答 Firefox canary 域名 `use-application-dns.net` 为 NXDOMAIN
（[Mozilla 说明](https://support.mozilla.org/en-US/kb/configuring-networks-disable-dns-over-https)），
外加一份 DoH 端点规则集硬拦。注意 canary 只是信号，用户手动指定 DoH 时会被忽略
（[CMU SEI](https://www.sei.cmu.edu/blog/dns-over-https-3-strategies-for-enterprise-security-monitoring/)）。

---

## 真要做 kill switch：这 7 条必须先就位（验收标准，不是建议）

项目里已有先例——里程碑 13 的「远程防板砖」（`SetModeGuarded`/`ConfirmMode` 死亡开关 +
`injectManagement` 管理端口豁免）。以下在其基础上加码：

1. **只用具名 anchor**（`pfctl -a trust-proxy`），**绝不碰 `/etc/pf.conf`**；一条
   `pfctl -a trust-proxy -F all` 能整份清掉。
2. **规则里永远预留生路**：lo0、API 口、`--management-ports`（SSH）、DHCP 67/68、
   当前默认网关、节点 IP。
3. **启用即武装死亡开关**：开启后 N 秒内没有 `confirm` 就自动卸载（复用 `SetModeGuarded`）。
4. **独立于我们二进制的看门狗**：十几行、能一眼审完的 launchd 脚本，检查心跳文件，
   超过 N 分钟无心跳就 flush anchor。它**不能依赖我们的进程健康**——「进程挂了」正是要防的场景。
5. **`trust-proxy unbrick`**：不需要 daemon 在跑，就是 flush anchor；启用时把这条命令直接打到终端上。
6. **默认不跨重启**：不写 pf.conf、不装开机加载。牺牲「重启窗口期的严格性」换一条确定的退路。
7. **VM 里验证最坏情况**：装规则 → `kill -9` 守护进程 → 断言 SSH 仍通 → 重启 → 断言网络恢复。
   tart VM 有图形控制台，SSH 被切也能进去救——**宿主机不具备这个条件，所以这类测试只能在 VM 做**。

---

## 已落地（观测侧，零系统改动）

| 能力 | 位置 / 入口 |
|---|---|
| 路由完整性（TunnelVision 形状） | `internal/netwatch` → kind=route、`trust-proxy netcheck` |
| LocalNet 越界 | 引擎 `checkLocalNetLocked` → kind=localnet |
| 客户端 DoH/DoT 绕过 | 引擎 `checkEncryptedDNSBypassLocked` → kind=dns-bypass |
| ECH 配置观测 | 解析路径 → `dns queries` 的 ECH 计数 |
| DNS 查询级（DGA 扫描 / 隧道） | `internal/detect/query.go` → kind=dns |
| JA4 指纹（ECH 后仍有效） | `internal/ja4` → kind=ja4、`detect fingerprints` |

阈值全部可配（`/api/detection-config`、`trust-proxy detect set`、Detection 页）。
**下一步不是急着上强制，而是先看这些观测在真实网络里报了什么**——有了数据再写强制规则，
才不是拍脑袋。
