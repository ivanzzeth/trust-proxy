# 桌面端（macOS）

```bash
make desktop     # -> desktop/src-tauri/target/release/bundle/{macos/Trust Proxy.app, dmg/*.dmg}
make desktop-dev # 开发运行（贴附已在跑的网关）
```

壳很薄：**只负责开窗和进程生命周期**，UI 就是网关自己在 `:9096` serve 的那个控制台。策略/检测一行都不在 Rust 里——否则一周内就会和 CLI 漂移。

## 两条不变量

| 不变量 | 为什么 | 怎么做 |
|---|---|---|
| **绝不起第二个网关** | 两个 `serve` 同数据目录会抢 `cache.db`（bolt 单写锁）和端口 | 先探 `/api/health`：有网关在跑就**贴附**（launchd 装的、终端里手起的都算），只有没人应答才拉起自己的 sidecar |
| **绝不留孤儿** | 关窗/强退后数据面还在跑 = 用户以为关了其实还在管流量 | 正常退出杀子进程；**SIGKILL/崩溃根本不跑回调**（实测 SIGTERM 掉壳后网关还活着），故 `serve --exit-with-pid <ppid>` 让子进程盯父进程 |

首启把内置默认配置写进 `<data>/config.json`，**已存在则绝不覆盖**（那是用户的东西）。起不来时把网关日志里最后一条错误**原样引到界面上**——最常见的是 17070 被别的代理占了，说清楚十秒能修。

## 安装：app 没有签名（也不打算签）

签名 + 公证需要 Apple Developer 会员（$99/年），**决定不做**。

| 从哪儿拿到 | 怎么装 |
|---|---|
| 自己 `make desktop` 构建 | 没有隔离标记，**双击直接开**，零操作 |
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
sudo trust-proxy service install -c ~/.trust-proxy/config.json   # LaunchDaemon
trust-proxy service status        # 装了没 / 在跑没 / 指向哪个二进制
sudo trust-proxy service uninstall   # 逃生口，任何状态都能收干净、幂等
```

app 上的按钮就是拿一次管理员授权跑上面这条 CLI（`osascript ... with administrator privileges`）。

**防板砖三条**：

1. **plist 绝不指向 `.app` 内部** —— install 把二进制拷到 **`/usr/local/libexec/trust-proxy`**（root:wheel 0755；临时文件 → chmod/chown → sha256 校验 → rename）再写 plist。否则你把 app 拖进废纸篓或升级替换，`KeepAlive` 会**每次开机重启一个不存在的程序**，只写日志不报错。按内容拷贝还顺带丢掉 `com.apple.quarantine`。`--keep-binary-path` 留给 Homebrew 这类本来就稳定的路径。
2. **`uninstall` 只删我们那份托管副本** —— 先读 plist 里的 program 再删；用户自己的二进制绝不碰。
3. **install 不会顺手打开 TUN** —— 不给 `--mode tun` 就不写这一项；给了会要求确认。

`service status` 会显式报 `program_missing`，因为这个状态否则只表现为开机时的静默重试循环。

## 还没做

代码签名/公证（**已决定不做**）、自动更新、Windows（服务 + UAC）与 Linux（systemd + polkit/setcap）的提权模型、菜单栏/托盘常驻。见 `docs/TODO.md` #4。
