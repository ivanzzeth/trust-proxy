# 节点：订阅导入 / 自建出口

## 订阅与节点解析

- **格式**：**sing-box JSON**（无损直取 outbounds）、**Clash YAML**（含单个粘贴的节点 dict）、base64/明文 **share 链**。
- **协议**：vless(reality)、vmess、trojan、shadowsocks、anytls、hysteria2、tuic —— 均覆盖 reality/tls/utls + ws/grpc。
- **来源**：http(s) URL、`file://` 本地路径、或直接粘贴内容。
- **抓取**用 **uTLS 伪装 Chrome 指纹**（`internal/subscription/fetch.go`）：部分机场做 TLS/HTTP 指纹识别，只放行 mihomo/clash/浏览器——curl 得风控页、裸 Go `net/http` 被 reset。已实测 JA4 与真 Chrome 一致，**无需外部工具**。`--via socks5://|http://` 可经指定代理出口抓取（绕开机场对来源 IP 的封锁，机房 IP 常被拦）。
- **apply**：把节点 outbound 注入配置、`proxy` 组重建为 urltest → **先建新 box 成功才关旧的**（配置错误则旧 box 完好、apply 报错，不中断服务）。

```bash
trust-proxy sub add <url> [--via socks5://…] [--ua …]
trust-proxy sub import [file]      # stdin 亦可
trust-proxy sub ls | apply <id> | refresh <id> | rm <id>
```

## 一键自建出口节点

**两半必须一次生成**：在出口机上跑一次 `proxy gen`、又在控制台里握着另一套密钥，两边永远连不上。所以由网关生成两半。

**控制台**：Nodes 页 →「自建出口」→ 填地址/端口 → 生成 → 复制部署脚本到你的 VPS 执行 → 点「添加为节点」。

**命令行**（离线可用，出口机上没网关在跑也行）：

```bash
trust-proxy proxy gen --type <协议> --server <你的服务器IP> --port 443
#   协议: shadowsocks | vless-reality | vless | vmess | trojan | anytls | hysteria2 | tuic
#   输出：服务端 config + 可直接部署的 shell 脚本 + 客户端节点(Clash dict) + share 链
#   TLS 类自动内联自签证书(客户端 skip-cert-verify)；vless-reality 免证书自动生成密钥对
#   --json 与 POST /api/proxy-gen 同形，方便脚本消费
```

在**出口机**上（需要该机器有 trust-proxy 二进制）：

```bash
# 直接粘贴上面输出的「deploy on the exit host」那段，或者手工等价：
trust-proxy proxy run -c server.json            # 前台
trust-proxy proxy run -c server.json -d         # 后台守护（脱离终端，SSH 断开不受影响）
trust-proxy proxy stop --pid trust-proxy.pid    # 停止
```

## 代理分组

`internal/proxygroups`：按国家自动分组 + **🌏 Overseas 共享组**（成员 = 国家不在排除列表里的节点）。Overseas 是「地区受限服务 failover」的载体——Anthropic/OpenAI 拒 HK/CN，geofenced 策略包走 Overseas，在允许地区之间自动切、绝不落到被封地区。默认排除 HK/MO/CN，Proxies 页可改。

sing-box 只有 `selector` / `urltest`，没有 load-balance。
