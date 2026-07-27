# 桌面端（macOS / Linux / Windows）

```bash
make app         # 构建 + 安装 + 打开（用 app 就这一条）
make build       # 全套：控制台 → 内嵌 UI 的单二进制 → 当前平台的 app
make build-app   # 只重打 app（macOS: .app + .dmg / Linux: .deb + .AppImage / Windows: .msi + .nsis）
make desktop-dev # 开发运行（贴附已在跑的网关）
```

`make app` 会先**退掉正在跑的那份再替换** —— `open` 一个已经在运行的 bundle 只是把旧进程调到前台，你会对着旧代码以为是新的（端口改号后那个卡在启动页的 app 就是这么来的）。装完还会检查一件事：**系统服务里跑的二进制如果比刚构建的旧**，就把这行打出来，因为壳会贴附到那个旧网关、窗口里一切看起来都正常：

```
==> note: the installed service still runs an older gateway:
      /usr/local/libexec/trust-proxy (v0.8.0-12-ge257201-dirty)
    the app attaches to that one, so the window would show the old code.
    update it too:  sudo ./trust-proxy service install --mode tun -y
```

**`make app` 不带 sudo，那 TUN 还能用吗？能 —— TUN 不是 app 给的。** 壳以你的身份跑（GUI 不该是 root），网关才需要 root：

| 机器上的状态 | app 做什么 | TUN |
|---|---|---|
| 已有 root 网关在跑（系统服务，或你 `sudo serve`） | **贴附**上去 | ✅ 由那个网关提供 |
| 什么都没跑 | 以**你的身份**拉起一个 sidecar | ❌ `can_tun:false`，控制台里 TUN 按钮直接给提权引导，而不是切到一半失败 |

所以要长期用 TUN 就装系统服务：launchd 拿着 root 网关，app 只是窗口，关窗不掉策略、重启自恢复。壳上那个「Install system service…」按钮就是拿一次管理员授权去跑同一条 CLI。**装之前它会先停掉自己拉起的那个网关** —— 否则端口和数据目录被占着，服务起不来，`KeepAlive` 会永远重试一个注定失败的进程，而窗口里一切正常（因为你看的是它自己那个网关）。装失败/你点了取消，它把原来那个再拉回来。

**同一个壳，三种提权方式**——壳本身在哪都不是 root，它只是请系统以 root 跑同一条 CLI 命令，再读回 CLI 自己的 JSON。这样「装出来的东西」不取决于是谁问的：

| 平台 | 提权 | 服务 | 机器级数据目录 |
|---|---|---|---|
| macOS | `osascript … with administrator privileges` | launchd LaunchDaemon | `/Library/Application Support/trust-proxy` |
| Linux | **`pkexec`**（polkit） | systemd unit | `/var/lib/trust-proxy` |
| Windows | **RunAs**（UAC） | 服务控制管理器(SCM) | `%ProgramData%\trust-proxy` |

Linux 上**故意不拿 `sudo` 兜底**：GUI 里没有终端可以问密码，结果要么静默失败，要么在配了免密 sudo 的机器上**不弹任何提示就提权**。没有 pkexec 时壳直接告诉你去终端敲哪条命令。

壳很薄：**只负责开窗和进程生命周期**，UI 就是网关自己在 `:21585` serve 的那个控制台。策略/检测一行都不在 Rust 里——否则一周内就会和 CLI 漂移。

## 两条不变量

| 不变量 | 为什么 | 怎么做 |
|---|---|---|
| **绝不起第二个网关** | 两个 `serve` 同数据目录会抢 `cache.db`（bolt 单写锁）和端口 | 先探 `/api/health`：有网关在跑就**贴附**（launchd 装的、终端里手起的都算），只有没人应答才拉起自己的 sidecar |
| **绝不留孤儿** | 关窗/强退后数据面还在跑 = 用户以为关了其实还在管流量 | 正常退出杀子进程；**SIGKILL/崩溃根本不跑回调**（实测 SIGTERM 掉壳后网关还活着），故 `serve --exit-with-pid <ppid>` 让子进程盯父进程 |

配置由**网关自己**解析和种下（`<data>/config.json`，已存在绝不覆盖）——壳既不传 `-c` 也不自带一份默认 JSON。它曾经两样都做，于是 CLI 和 app 各有一套默认值；见 [`operations.md`](operations.md)「配置在哪」。起不来时把网关日志里最后一条错误**原样引到界面上**——最常见的是 21584 被别的代理占了，说清楚十秒能修。

## 安装：app 没有签名（也不打算签）

签名 + 公证需要 Apple Developer 会员（$99/年），**决定不做**。

| 从哪儿拿到 | 怎么装 |
|---|---|
| 自己 `make build` 构建 | 没有隔离标记，**双击直接开**，零操作 |
| 别人给的 / 下载的 `.dmg` | 需放行一次，见下 |

```bash
xattr -dr com.apple.quarantine "/Applications/Trust Proxy.app"
```

或：双击 → 被拦 → **系统设置 → 隐私与安全性 → 底部「仍要打开」**。
⚠️ **macOS 15 起「右键→打开」对未公证 app 已失效**，只剩这两条路。

**别漏 `-r`**：bundle 里有两个可执行文件（壳 + Go 网关）。只放行 app 本身不够 —— 实测 macOS 26 会把网关那个直接 SIGKILL（macOS 15 不会），症状是「app 开着但一直显示网关起不来」。app 检测到这种情况会把该敲的命令连路径打在界面上。

ad-hoc 签名形态、真要签名/公证的完整流程见 [`release-macos.md`](release-macos.md)。

## TUN 需要 root：装成系统服务

GUI 不该是 root，所以提权交给系统 —— launchd 拥有 daemon，壳只贴附（关窗不掉策略、开机自启）：

```bash
sudo trust-proxy service install     # LaunchDaemon；配置默认 <data>/config.json
trust-proxy service status        # 装了没 / 在跑没 / 指向哪个二进制
sudo trust-proxy service uninstall   # 逃生口，任何状态都能收干净、幂等
```

app 上的按钮就是拿一次管理员授权跑上面这条 CLI（`osascript ... with administrator privileges`）。

**防板砖三条**：

1. **plist 绝不指向 `.app` 内部** —— install 把二进制拷到 **`/usr/local/libexec/trust-proxy`**（root:wheel 0755；临时文件 → chmod/chown → sha256 校验 → rename）再写 plist。否则你把 app 拖进废纸篓或升级替换，`KeepAlive` 会**每次开机重启一个不存在的程序**，只写日志不报错。按内容拷贝还顺带丢掉 `com.apple.quarantine`。`--keep-binary-path` 留给 Homebrew 这类本来就稳定的路径。
2. **`uninstall` 只删我们那份托管副本** —— 先读 plist 里的 program 再删；用户自己的二进制绝不碰。
3. **install 不会顺手打开 TUN** —— 不给 `--mode tun` 就不写这一项；给了会要求确认。

`service status` 会显式报 `program_missing`，因为这个状态否则只表现为开机时的静默重试循环。

## 各平台的系统服务

三条路径共用同一套 `Config` 和同一批防板砖规则（托管副本、一条命令卸干净、install 不会顺手开 TUN）：

```bash
sudo trust-proxy service install     # macOS launchd / Linux systemd / Windows SCM（Windows 需管理员命令行）
trust-proxy service status           # 装了没 / 在跑没 / 指向哪个二进制（--json 里字段名是 file）
sudo trust-proxy service uninstall   # 逃生口
```

- **Linux**：写 `/etc/systemd/system/trust-proxy.service` 并 `enable --now`。`Restart=always` 对应 launchd 的 `KeepAlive`；只挂 `After=network.target`，**绝不等 `network-online.target`**——在「我们就是网络出口」的机器上那个 target 可能永远不到，网关就永远不启动。ExecStart 里的路径是**带引号**的：systemd 按空白拆参数并展开 `%` 说明符，`/home/ivan/My Gateway/data` 不加引号会被拆成两个参数，然后网关用错的数据目录起来了，还不报错。TUN 所需能力用 `AmbientCapabilities` 精确给（`CAP_NET_ADMIN`/`NET_RAW`/`NET_BIND_SERVICE`），其余丢掉。
- **Windows**：SCM 服务不是「系统帮你起的进程」——它必须回报 Running 并处理 Stop，否则启动超时后被 SCM 杀掉（表现为「服务起不来」，且哪个日志里都没线索）。所以服务是用 `serve --windows-service` 启的；Stop 时先让网关收尾再报 Stopped（TUN 模式下有一张网要还原，中途被杀就是一台没有路由的机器）。失败自动重启 = SCM 的 recovery actions。
- **数据目录**：`service install` 默认用**机器级**目录（boot 时可能还没人登录，家目录未必可读）。若检测到你已有 `~/.trust-proxy` 数据，会**问一句要不要拷过去**——拷贝而非移动，服务不合用时你还有一个能跑的个人网关；`cache.db`（bolt 单写锁）和 pid/log 刻意不拷。

回归测试（缺依赖一律 **skip 而非失败**）：

| 命令 | 覆盖 |
|---|---|
| `make e2e-desktop` | **打出来的 `.app` 本身**：壳会去探的地址 vs 网关真正的默认端口、bundle 里的 sidecar 是不是带内嵌控制台（连 `/assets/*` 真的能取到）、壳与 sidecar 是不是同一次构建。`TP_DESKTOP_GUI=1` 再加一条真启动壳、断言它**贴附**而不是另起一个网关（默认跳过，因为会弹窗）。 |
| `make e2e-macos` | tart VM 里真装 launchd + TUN 死亡开关 |
| `make e2e-linux` | 特权容器里 pid 1 = 真 systemd：install → `kill -9` 后自愈 → TUN 真捕获 → 卸载干净 |

`e2e-desktop` 是补上一个真实教训：端口改号后，`/Applications` 里那份旧 bundle 仍在探 9096，于是**永远卡在「启动网关」**——而当时所有其它测试都是绿的，因为没有一个去看过 `.app`。壳因此多了一个 `--print-config`（打印它会连的地址、数据目录、sidecar 路径就退出，不开窗），既给测试用，也是用户报「打不开」时第一个该问的东西。

## 还没做

代码签名/公证（**已决定不做**）、自动更新、菜单栏/托盘常驻。**Windows 的提权与服务代码尚未在真 Windows 上跑过**（这里没有 Windows 机器）——三平台都能编译、vet 通过，纯字符串部分（参数表、引号处理）有跨平台单测。见 `docs/TODO.md` #4。
