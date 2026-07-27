# 桌面端（macOS / Linux / Windows）

> **状态**：macOS 在真机验证过（`make e2e-macos` 在 tart VM 里跑真 launchd + 真 TUN，`make e2e-desktop` 检查打出来的 `.app`）。**Linux / Windows 桌面尚未验证**，CI 也还不出桌面包 —— 这两个平台今天请用 `sudo trust-proxy install`，装完 app 打开就是零提示贴附。见文末「还没做」。

```bash
make app         # 构建 + 安装 + 打开（目前只有 macOS 会真的安装；其它平台只跑一下 target/release 里的开发二进制）
make build       # 全套：控制台 → 内嵌 UI 的单二进制 → 当前平台的 app
make build-app   # 只重打 app（macOS: .app + .dmg / Linux: .deb + .AppImage / Windows: .msi + .nsis）
make desktop-dev # 开发运行（贴附已在跑的网关）
```

`make app` 会先**退掉正在跑的那份再替换** —— `open` 一个已经在运行的 bundle 只是把旧进程调到前台，你会对着旧代码以为是新的（端口改号后那个卡在启动页的 app 就是这么来的）。它还会在装完提醒一句「系统服务里跑的二进制比刚构建的旧」；这个提醒后来长进了产品本身，见下面的 `update` 一态 —— 开发机上的 Makefile 提示解决不了用户下载一个新版本的情况。

**app 从不以 root 跑，TUN 也不是它给的。** 壳是一个窗口加一次授权；网关是系统服务，root 由服务管理器持有。

打开 app 之后只有四种结局，全部由 `trust-proxy env --json` 的 `action` 字段决定 —— **壳不自己判断**：

| `action` | 机器上是什么 | 壳给什么 |
|---|---|---|
| `attach` | 系统服务在跑，且和这个 app 同一个 build | 直接开控制台，**零提示**，而且是已登录的（一次性 ticket 换 cookie） |
| `update` | 服务在跑，但**比这个 app 旧** | 「Update the gateway…」 |
| `takeover` | 端口上有网关，但不是托管副本（终端里手起的、或旧版本留下的） | 「Take over and set up…」 |
| `install` | 什么都没有 | 「Set up…」／「Set up, with TUN capture…」 |
| `repair` / `unsupported` | 装了没跑 / 本平台没实现服务 | 说清楚，并给出唯一能做的事 |

后四种跑的是**同一条 `sudo trust-proxy install`**（它幂等，重跑就是升级），所以一律是**一次系统授权、零敲命令**。任何时候都还有一个「Open the console anyway」—— 一个陈旧或陌生的网关是在跑着的、能用的，不该变成一堵墙。

为什么 `update` 值得单独一态：没有它，升级是**静默空操作** —— 新 app 探到健康网关就贴附，显示旧 daemon 的控制台，每一页都对，新二进制一次没被用上。`/api/health` 因此对 loopback 报自己的 version 和「我是不是托管副本」（对外网不报：给未认证的扫描器一个精确版本号是白送打靶信息）。

**壳不跑网关。** 它曾经会：没人应答就以登录用户身份拉起 sidecar。那个网关是假的——没有 TUN（要 root）、关窗即死、还往 `~/.trust-proxy` 写文件，于是任何人 `sudo` 跑过一次之后，目录归 root，app 再也起不来。整条路径连同那段「你的数据目录不可写」的道歉信一起删了 —— 那个状态本来就是它自己造的。

## 一条不变量：一台机器一个网关

两个 `serve` 共用一个数据目录会抢 `cache.db`（bolt 单写锁）和端口，而你看着的那个不一定是正在管流量的那个。所以壳只贴附或安装，从不新起；`install` 会把占着 API 端口的那个先停掉，并且等它**进程真的退出** —— 只等端口释放的话，旧网关还在收尾、新服务已经绑上，中间那段两个进程共用一把锁。

停它的时候按可靠性依次问三处：**问网关自己**（`/api/health` 对 loopback 报 pid）→ pid 文件 → 问操作系统谁在监听。以前只有中间那一条，而终端里手起的网关根本不写 pid 文件，**且失败时会把已有的那份删掉** —— 单向棘轮，每重试一次少一条线索，最后把人赶回命令行。

（以前还有第二条「绝不留孤儿」，靠 `serve --exit-with-pid` 让子进程盯着壳的 pid。壳不再有子进程了，这条随之消失 —— 最好的不变量是**没有那个东西**。）

想连那一次授权都省掉：走系统安装器（`.pkg` / `.deb` / `.msi`），安装器本身是提权的，服务在**装的时候**就位，之后双击 app 永远零提示。这也是 CI 该出的包（还没出，见文末）。

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
sudo trust-proxy install      # 装 + 启动 + 开机自启 + 认领（幂等，重跑就是升级）
trust-proxy env               # 这台机器是什么状态、下一步该干什么
sudo trust-proxy uninstall    # 逃生口，任何半装状态都能收干净、幂等，数据一行不动
```

app 上的按钮就是拿一次管理员授权跑上面第一条 CLI（macOS 走 `osascript ... with administrator privileges`）——**同一条命令**，所以装出来的东西不取决于是谁问的。

**防板砖三条**：

1. **plist 绝不指向 `.app` 内部** —— install 把二进制拷到 **`/usr/local/libexec/trust-proxy`**（root:wheel 0755；临时文件 → chmod/chown → sha256 校验 → rename）再写 plist。否则你把 app 拖进废纸篓或升级替换，`KeepAlive` 会**每次开机重启一个不存在的程序**，只写日志不报错。按内容拷贝还顺带丢掉 `com.apple.quarantine`。`--keep-binary-path` 留给 Homebrew 这类本来就稳定的路径。
2. **`uninstall` 只删我们那份托管副本** —— 先读 plist 里的 program 再删；用户自己的二进制绝不碰。
3. **install 不会顺手打开 TUN** —— 不给 `--mode tun` 就不写这一项；给了会要求确认。

`service status` 会显式报 `program_missing`，因为这个状态否则只表现为开机时的静默重试循环。

## 各平台的系统服务

三条路径共用同一套 `Config` 和同一批防板砖规则（托管副本、一条命令卸干净、install 不会顺手开 TUN）：

```bash
sudo trust-proxy install      # macOS launchd / Linux systemd / Windows SCM（Windows 需管理员命令行）
trust-proxy service status    # 装了没 / 在跑没 / 指向哪个二进制（--json 里字段名是 file）
sudo trust-proxy uninstall    # 逃生口
```

（`service install` / `service uninstall` 作为隐藏别名保留，老笔记和脚本还能用。）

- **Linux**：写 `/etc/systemd/system/trust-proxy.service` 并 `enable --now`。`Restart=always` 对应 launchd 的 `KeepAlive`；只挂 `After=network.target`，**绝不等 `network-online.target`**——在「我们就是网络出口」的机器上那个 target 可能永远不到，网关就永远不启动。ExecStart 里的路径是**带引号**的：systemd 按空白拆参数并展开 `%` 说明符，`/home/ivan/My Gateway/data` 不加引号会被拆成两个参数，然后网关用错的数据目录起来了，还不报错。TUN 所需能力用 `AmbientCapabilities` 精确给（`CAP_NET_ADMIN`/`NET_RAW`/`NET_BIND_SERVICE`），其余丢掉。
- **Windows**：SCM 服务不是「系统帮你起的进程」——它必须回报 Running 并处理 Stop，否则启动超时后被 SCM 杀掉（表现为「服务起不来」，且哪个日志里都没线索）。所以服务是用 `serve --windows-service` 启的；Stop 时先让网关收尾再报 Stopped（TUN 模式下有一张网要还原，中途被杀就是一台没有路由的机器）。失败自动重启 = SCM 的 recovery actions。
- **数据目录**：只有机器级一个（boot 时可能还没人登录，家目录未必可读）。旧的 `~/.trust-proxy` 会被 `install` **一次性收编**（拷贝不移动，已有的不覆盖，只拷 `*.json` 策略）。**不问**——这条命令一半时间跑在没有终端的授权框后面，一个没人能回答的问题就是一次失败的安装。

回归测试（缺依赖一律 **skip 而非失败**）：

| 命令 | 覆盖 |
|---|---|
| `make e2e-desktop` | **打出来的 `.app` 本身**：壳会去探的地址 vs 网关真正的默认端口、bundle 里的 sidecar 是不是带内嵌控制台（连 `/assets/*` 真的能取到）、壳与 sidecar 是不是同一次构建。`TP_DESKTOP_GUI=1` 再加一条真启动壳、断言它**贴附**而不是另起一个网关（默认跳过，因为会弹窗）。 |
| `make e2e-macos` | tart VM 里真装 launchd + TUN 死亡开关 |
| `make e2e-linux` | 特权容器里 pid 1 = 真 systemd：install → `kill -9` 后自愈 → TUN 真捕获 → 卸载干净 |

`e2e-desktop` 是补上一个真实教训：端口改号后，`/Applications` 里那份旧 bundle 仍在探 9096，于是**永远卡在「启动网关」**——而当时所有其它测试都是绿的，因为没有一个去看过 `.app`。壳因此多了一个 `--print-config`（打印它会连的地址、数据目录、sidecar 路径就退出，不开窗），既给测试用，也是用户报「打不开」时第一个该问的东西。

## 还没做

代码签名/公证（**已决定不做**）、自动更新、菜单栏/托盘常驻。

**Linux / Windows 桌面还不算做完**，三件事：

1. **CI 不出桌面包** —— 只出 4 个 CLI 二进制，所以没有可下载的 Linux/Windows app。
2. **`.deb` / `.msi` 的 postinst 里应该顺手把服务装好** —— 安装器本身是提权的，那样 app 首次打开也是零提示，比 macOS 的拖拽安装还顺。
3. **AppImage + pkexec 没验证**：sidecar 在 `/tmp/.mount_*` 的 FUSE 挂载里，root 大概率读不到（推断，未实测）。`bundle.targets` 现在是 `"all"`，会出一个可能打不开的包 —— 要么验证要么去掉。

`cargo test` 已经进 CI（`.github/workflows/test.yml`），因为壳的提权是 `cfg(target_os)` 分支：**Linux 那段 pkexec 代码在 macOS 开发机上一次都没被编译过**。Windows 的提权与服务代码同样没在真 Windows 上跑过。见 `docs/TODO.md` #4。
