# macOS 分发：签名 / 公证 / 不签名怎么办

`make desktop` 产出 `desktop/src-tauri/target/release/bundle/` 下的 `Trust Proxy.app` 与 `.dmg`。
本文只讲**怎么让别人能打开它**。

---

## 现状（未签名，默认）

`make desktop` 默认 `APPLE_SIGNING_IDENTITY=-`，即 **ad-hoc 签名**：

```
$ codesign -dv "Trust Proxy.app"
CodeDirectory ... flags=0x10002(adhoc,runtime)   # hardened runtime 已开
Signature=adhoc
Sealed Resources version=2 rules=13 files=2      # bundle 封印完整
$ codesign --verify --deep --strict "Trust Proxy.app"   # valid on disk
$ spctl -a -t exec "Trust Proxy.app"                    # rejected（预期：未公证）
```

为什么**必须**至少 ad-hoc：Apple Silicon 上没有任何签名的 Mach-O **根本无法执行**；
而不给 Tauri 传 identity 时它不封印 bundle，`spctl` 会报
`code has no resources but signature indicates they must be present`——连评估都做不了。
ad-hoc 不等于公证，但至少形态正确、错误信息可读，以后换成真证书也不用改流程。

### 别人拿到未签名 app 怎么装

自己本机 `make desktop` 出来的：**没有隔离标记，双击直接开**（无需任何操作）。

从浏览器/AirDrop/dmg 拿到的：文件带 `com.apple.quarantine`，Gatekeeper 会拦一次。二选一：

```bash
# 一条命令清掉（推荐给会开终端的人）
xattr -dr com.apple.quarantine "/Applications/Trust Proxy.app"
```

或者：双击 → 被拦 → **系统设置 → 隐私与安全性 → 仍要打开**。
注意 **macOS 15 起「右键→打开」这个老捷径对未公证 app 已失效**，只能走系统设置那条路。

### 实测到的坑（不是传闻）

我们的壳会**再启动一个可执行文件**（Go 网关 sidecar），而「批准这个 app」不一定顺延到它：

| 系统 | 隔离状态下命令行执行 sidecar |
|---|---|
| macOS 15.7.7（全新机器） | 正常，exit 0 |
| macOS 26.4.1 | **被 SIGKILL（exit 137）**，且日志里什么都没有 |

症状是「app 开着，但一直显示网关起不来」。所以壳会自己检查 bundle 上的隔离标记，
在这种情况下**直接把上面那条 `xattr -dr` 命令连路径打到界面上**（`quarantine_hint`），
而不是让人从 `signal: 9` 去猜。

---

## 要正式签名 + 公证（$99/年）

### 需要准备
1. **Apple Developer Program** 会员。
2. **Developer ID Application** 证书（不是 "Mac App Distribution"，那是上架用的）。导出 `.p12`。
3. 公证凭据，二选一：
   - **App Store Connect API Key**（推荐）：`AuthKey_XXXX.p8` + Key ID + Issuer ID，可单独撤销；
   - Apple ID + **app-specific password**（`appleid.apple.com` 生成，别用主密码）+ Team ID。

### 本机一把梭

```bash
export APPLE_SIGNING_IDENTITY="Developer ID Application: Your Name (TEAMID)"
# CI 上没有钥匙串时再给这两个：
# export APPLE_CERTIFICATE="$(base64 -i cert.p12)" APPLE_CERTIFICATE_PASSWORD='…'

# 公证（API Key 方式）
export APPLE_API_KEY=ABCD1234EF
export APPLE_API_ISSUER=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export APPLE_API_KEY_PATH=/abs/path/AuthKey_ABCD1234EF.p8

make build-app          # Tauri 自己 codesign → notarytool submit --wait → stapler staple
```

要点：
- **hardened runtime 必开**（`--options runtime`），否则公证直接拒。我们 ad-hoc 阶段就已经开着了。
- **bundle 里每个可执行文件都要签**，包括 ~81MB 的 Go sidecar；顺序先内后外。Tauri 会递归处理。
- 必须带**安全时间戳**（默认开），否则证书过期后签名失效。
- 我们不用 App Sandbox，因此基本不需要 entitlements。

### 验收三连

```bash
codesign -dvvv --strict "Trust Proxy.app"   # Authority 链里应出现 Developer ID Application
spctl -a -vvv -t exec "Trust Proxy.app"     # accepted, source=Notarized Developer ID
xcrun stapler validate "Trust Proxy.app"    # 装订成功后离线也能验
```

被拒时看逐文件原因：

```bash
xcrun notarytool log <submission-id> --key … --key-id … --issuer …
```

---

## 板砖坑（已修）

`service install` 曾把 plist 的 `ProgramArguments[0]` 写成**当前二进制路径**——从 app 里点安装就是
`/Applications/Trust Proxy.app/Contents/MacOS/trust-proxy`。app 一旦被移动/删除/升级替换，
daemon 就指向空气，而 `KeepAlive` 会**每次开机都重启一个不存在的程序**，失败只写进没人看的日志。

现在 install 把二进制**拷到 `/usr/local/libexec/trust-proxy`（root:wheel，0755）**再写 plist：
先写临时文件 → chmod/chown → sha256 比对 → `rename` 落地（半个二进制被 launchd 捡去会在开机时炸）。
按内容拷贝而非 symlink（symlink 会以同样方式断），顺带**丢掉 `com.apple.quarantine`**（xattr 不属于文件内容），
这正好治了上面那个「隔离的 sidecar 被 SIGKILL」。
`--keep-binary-path` 可保留原路径（给 Homebrew 这类本来就稳定的安装用）。

`uninstall` 先读 plist 里的 program 再删 plist，**只删我们那份托管副本**——用户自己的二进制绝不碰。
`service status` 会显式报 `program_missing`，因为这个状态否则只表现为开机时的静默重试循环。

VM 实测：从 bundle 内安装 → plist 指向 `/usr/local/libexec/trust-proxy`(root:wheel) → **把整个 .app 删掉后
`launchctl kickstart` 依然起得来** → uninstall 收走副本且不误删用户二进制。

---

## 许可证

签名/公证与 GPLv3 不冲突。分发物仍须随附对应源码——`.dmg` 的 copyright 字段已带源码地址
（`tauri.conf.json` 的 `bundle.copyright`），签名不影响这一点。
