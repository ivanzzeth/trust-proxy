# Kubernetes：节点级网关（DaemonSet）

给集群里的每个 Pod 一条**出网加速**路径（默认 **Split** 位姿：L3 闸开着，L1 底线还在），**应用零改造**——不改 Deployment、不设
`HTTPS_PROXY`、不注入 sidecar。Pod 照常 `curl`，包在离开节点前就已经过了检测引擎和出口选择。

> ⚠️ Chart / 产品默认是 **Split**。**Strict**（默认拒绝）在 `mode=tun` 下会把 kubelet/DNS/CNI
> 当普通出网一起掐死 → 节点 `NotReady`。只有你明确知道 managementPorts 盖全了才改 `posture=strict`。

---

## 为什么是 DaemonSet 而不是一个中心出口 Service

Pod 出网的内核路径是 `veth → CNI bridge → forward 链`。

这是**关键的一句**：网关自己进程出网走的是 nftables 的 **output 链**，而 Pod 的流量是**被转发的**，
走 **prerouting/forward 链**。两条链完全不同，能捕获前者的配置对后者一点作用都没有——
`auto_redirect`（sing-tun 的 nftables 重定向）存在的唯一理由就是后者。

所以网关必须**在节点上**（`hostNetwork` + `NET_ADMIN` + `/dev/net/tun`），而不是在节点前面。
一个中心出口 Service 要求每个应用显式把流量发过去，那就不是「零改造」，而且**漏掉的那个应用是静默的**。

这条主张是被测出来的，不是推出来的：`test/linux_tun_docker_test.go`
（`make e2e-tun`，CI 每次跑）在容器里用 netns + bridge 搭出与 K8s Pod **完全同构**的转发路径，
断言默认拒绝拦得住、Permit 之后通、no-proxy 不开闸、LAN 不受影响，最后**关掉 `auto_redirect`
就必须失去这个能力**（最后这条是给前面几条验牙的）。

---

## 「一台机器一个网关」在容器里的那个例外

铁律说入口只有 `sudo trust-proxy install`。镜像的 ENTRYPOINT 却是 `serve`，这是**例外不是绕过**：

`install` 在裸机上做四件事——拷托管副本、注册服务、开机自启、收编旧数据——它们存在是因为
**裸机上没有别的东西托管这个进程**。在 K8s 里 kubelet 就是那个东西：Pod spec 就是服务定义，
`imagePullPolicy` 就是托管副本，`restartPolicy` 就是自愈，hostPath/PVC 就是数据目录。
在容器里跑 `install` 等于在一个没有 systemd 的文件系统里注册一个重启即消失的 unit。

`serve` 是 hidden 的、非特权调用会指向 `install`——那条拒绝是按**能不能写数据目录**判断的
（`resolveDataDir`），容器里是 root，所以不触发。

---

## 前提

| 项 | 要求 |
|---|---|
| 节点内核 | Linux，有 `/dev/net/tun`，**内核** nftables 可用（initContainer 会替你确认；**不需要**节点上装 `nft` 命令行包，见下） |
| CNI | bridge 类（Flannel / Calico / Cilium 均可）。Pod 出网必须经过节点的 forward 链 |
| 权限 | `hostNetwork`、`hostPID`、`NET_ADMIN`、`NET_RAW`。Pod Security Admission 下这就是 `privileged` |
| 镜像 | `ghcr.io/ivanzzeth/trust-proxy:<tag>`，amd64 + arm64 |

---

## ⚠️ 装之前必须先看的两件事：`posture` + `--management-ports`

**Chart 默认 `posture=split`。** Split 跳过 L3 Permit 闸，节点不会因为漏端口就 NotReady。
只有你改成 `posture=strict` 时，下面这条才变成「最可能板砖」：

网关在 Strict 下默认拒绝出网。在 `hostNetwork` 的节点上，「让这个节点还是集群成员」的流量——kubelet 连
API server、CoreDNS 查上游、CNI 的 overlay、etcd 互连——**也只是流量**，一样会被闸拦下。
被拦下的结果是节点 `NotReady`，而你可能已经没法 SSH 进去了。

`--management-ports` 列出的源端口在 **L0**（所有规则之上）直接 `direct`，绕过闸、绕过黑名单、
绕过检测。manifests 与 chart 给的保守默认：

```
22     ssh —— 出事时你还进得去
53     DNS
6443   kube-apiserver
10250  kubelet
10256  kube-proxy health
2379   etcd client   (控制面节点)
2380   etcd peer     (控制面节点)
```

**这只覆盖 stock kubeadm。** 你的集群还需要什么，装之前自己查一遍：

| 组件 | 端口 |
|---|---|
| Calico BGP | 179 |
| Cilium health / VXLAN | 4240 / UDP 8472 |
| Flannel VXLAN | UDP 8472 |
| WireGuard 型 CNI | 视配置 |
| 云厂商 metadata / LB 健康检查 | 视厂商 |

```bash
# 装之前，在目标节点上看一眼它到底在跟谁说话
ss -tunp | awk '{print $5}' | sort -u | head -50
```

**≥32768 的端口会被网关拒绝**（chart 在渲染时就拒绝，不等到 CrashLoopBackOff）：
那是内核分给普通出站连接的临时端口范围，把它豁免等于把一切豁免，闸就不再有任何意义。

---

## 安装

### 方式 A：kubectl（原始 manifests）

```bash
kubectl apply -k deploy/kubernetes

# API token（必须，除非是实验环境）
kubectl -n trust-proxy create secret generic trust-proxy \
  --from-literal=api-token="$(openssl rand -hex 32)"
```

### 方式 B：Helm

```bash
helm install trust-proxy deploy/helm/trust-proxy \
  --namespace trust-proxy --create-namespace \
  --set 'managementPorts={22,53,6443,10250,10256,2379,2380,179}'

kubectl -n trust-proxy create secret generic trust-proxy \
  --from-literal=api-token="$(openssl rand -hex 32)"
kubectl -n trust-proxy rollout restart ds/trust-proxy
```

**装完什么都不会被调度。** 节点靠打标签逐台加入：

```bash
kubectl label node <node> trust-proxy.io/gateway=true
```

默认不是「装全集群」，这是刻意的。一个 Deployment 出问题不影响集群本身；
一个出网网关出问题会带走节点的网络，而**你没法修一台已经连不上的机器**。

---

## 自检清单（按顺序，第 1 条必须最先）

### 1. 节点还是不是集群成员

```bash
kubectl get node <node>            # 还 Ready 吗？
kubectl -n trust-proxy logs -l app.kubernetes.io/name=trust-proxy -c gateway --tail=50
```

`NotReady` = 某个管理端口没豁免。这条排第一，因为它出事最贵、最难恢复。

**回滚**（在节点上直接执行，不依赖 API server）：

```bash
crictl ps | grep trust-proxy       # 或 docker ps
crictl stop <id>
# 进程一死，utun 消失、nftables 表被清、路由回落 —— 出网恢复无策略状态
```

真的锁死了：`kubectl label node <node> trust-proxy.io/gateway-` 让 DaemonSet 撤掉这个 Pod。
（前提是 API server 还能到——所以 6443/10250 的豁免不能省。）

### 2. 网关自己认为它在捕获

```bash
kubectl -n trust-proxy exec ds/trust-proxy -- trust-proxy status --json
kubectl -n trust-proxy exec ds/trust-proxy -- trust-proxy doctor nftables
```

期望 `mode: tun`、`can_tun: true`、`usable: yes`。

initContainer 已经查过 nftables 了——它查不过 Pod 就起不来，这是刻意的：
**缺 nftables 时网关照样启动、照样报健康，而每个 Pod 的流量都从它旁边流走**，
那是最坏的中间状态，因为它看起来正是最好的那个。

`usable` 问的是**内核**能不能被编程，探测方式与 sing-tun 自己启动 `auto_redirect` 前跑的
那一次逐字相同（`nftables.New()` + `ListTablesOfFamily()`，走 netlink）。它**不要求节点或
镜像里有 `nft` 命令行**——sing-tun 从不 exec 它，镜像里带着它只是为了出事时你能 `nft list
ruleset` 看一眼。这条区分是 e2e 逼出来的：早先的探测查的是 `nft` 在不在 PATH、
`/proc/net/netfilter/nf_tables` 能不能 stat，结果在一个**转发流量确实被捕获**的容器里
两条都不成立，于是 preflight 会拒绝一台好节点——正是它想防的那件事的反面。

### 3. 默认拒绝对 Pod 真的生效

```bash
kubectl run probe --rm -it --restart=Never \
  --overrides='{"spec":{"nodeSelector":{"trust-proxy.io/gateway":"true"}}}' \
  --image=curlimages/curl -- curl -sS -m 10 https://example.com
```

**期望它失败。** 如果它成功了，说明转发流量绕过了网关——这时候要看的是 initContainer 的输出
和 `nft list table inet sing-box`，不是网关日志（网关会说自己一切正常，它没说错，它只是没看见这些包）。

然后放行一个目的地，再跑一次：

```bash
kubectl -n trust-proxy exec ds/trust-proxy -- trust-proxy acl add permit example.com --type domain
# 重跑上面的 probe —— 现在应该 200
```

### 4. 「加速」这半

到这里 Pod 的出网已经在闸后面了，但还是直连。加上出口节点：

```bash
kubectl -n trust-proxy exec ds/trust-proxy -- trust-proxy sub add <订阅URL>
kubectl -n trust-proxy exec ds/trust-proxy -- trust-proxy sub ls
kubectl -n trust-proxy exec ds/trust-proxy -- trust-proxy sub apply <id>
```

apply 之后，被 Permit 放行的流量走 `proxy` 组（urltest 自动选最快节点，按**真实流量**打分而非
`generate_204` 探测，见 `internal/proxyscore`）。

**地区受限的服务**（Anthropic / OpenAI / Cursor 拒 HK/CN）走 `🌏 Overseas` 共享组，
在允许的地区之间自动 failover，绝不落到被封的地区：

```bash
kubectl -n trust-proxy exec ds/trust-proxy -- trust-proxy rules packs ls       # 有哪些策略包
kubectl -n trust-proxy exec ds/trust-proxy -- trust-proxy rules packs apply Claude   # 名字大小写敏感
kubectl -n trust-proxy exec ds/trust-proxy -- trust-proxy proxies scores       # 每个节点凭什么是这个分
```

对集群里的应用来说，这一整套是**不可见的**：它 `curl api.anthropic.com`，包在节点上被捕获、
过闸、挑一个可用地区的出口发出去。应用侧一行配置都没有。

### 5. 打开控制台

```bash
kubectl -n trust-proxy port-forward ds/trust-proxy 21585:21585
open http://127.0.0.1:21585
```

`hostNetwork` 意味着 `http://<node-ip>:21585` 也能开——**这正是 API token 不可省的原因**。
没有 token 时，能连上那个端口就等于能改这个节点的出网策略。

### 6. 逐步铺开 + 确认能干净卸载

先在一台上跑够久（至少一次完整的业务高峰），再逐台打标签。

```bash
helm uninstall trust-proxy -n trust-proxy
# 或 kubectl delete -k deploy/kubernetes

# 在节点上确认真的干净了：
ip link show | grep -c tun          # 应为 0（或只剩别的工具的）
nft list table inet sing-box        # 应为 "No such file or directory"
```

数据目录 `/var/lib/trust-proxy` **不会被删**——那是这个节点的策略和历史，
和「一台机器一个网关」那边的规矩一致：卸载一条命令收干净，数据一行不动。

---

## 多节点：一个控制台管全集群

**零新代码**，用已有的多网关能力（`internal/nodes` + `/api/nodes/{id}/*` 反代 + Fleet 页）：

挑一个网关当「大脑」，把其余节点注册进去：

```bash
trust-proxy node add node-2 http://<node-2-ip>:21585 --token <api-token>
```

浏览器仍然只连一个 origin，token 由后端注入，不下发到前端。

**注意**：DaemonSet 的每个 Pod 都是一个**独立**网关，各自持有各自节点的策略。
Service 因此是 headless 的——一个 ClusterIP 会在不同节点的策略之间轮询，
刷新一次看到的是另一台的连接，而写操作落到哪台取决于谁应答，失败得很安静。

---

## 常见问题

**Pod 起不来，卡在 initContainer**
→ 节点**内核**的 nftables 不可用（不是「没装 `nft` 包」——那个不影响捕获）。
`kubectl -n trust-proxy logs <pod> -c preflight` 会打出 netlink 探测的原始错误：
`operation not permitted` 一般是 securityContext 少了 `NET_ADMIN`，
其余多半是内核缺 `nf_tables` 模块。真的不想要捕获转发流量就用 `mode=manual`
（只开代理入站，应用显式设 `HTTPS_PROXY`），此时 `preflight.enabled=false` 才被允许。

**节点变 NotReady**
→ 管理端口没豁免。见上面第 1 条的回滚，然后补 `managementPorts`。

**Pod 能出网但没经过网关**
→ 转发路径没被捕获。`nft list table inet sing-box` 看表在不在、`chain prerouting` 有没有规则；
`tun get` 确认 `auto_redirect: true`。

**改了 Secret 但 token 没生效**
→ `--api-token` 是启动时读的。`kubectl -n trust-proxy rollout restart ds/trust-proxy`，
一次一台（`maxUnavailable: 1`），过程中集群不会整体断网。

**Pod 重启后策略全没了**
→ `persistence.enabled=false`（emptyDir）。默认是 hostPath，不该出现这种情况。

---

## 相关

- `deploy/kubernetes/` — 原始 manifests，`kubectl apply -k`
- `deploy/helm/trust-proxy/` — chart，`values.yaml` 里每个旋钮都有一句人话
- `test/linux_tun_docker_test.go` — 转发路径捕获的 e2e（`make e2e-tun`）
- `docs/egress-enforcement-risks.md` — 为什么「转发失败即 drop」这类强制手段仍然暂缓
- `docs/nodes.md` — 订阅、自建出口、代理分组
