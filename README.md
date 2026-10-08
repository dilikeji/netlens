# netlens
流量监测工具,抓包工具,虚拟网卡模式

(作者:WorkBuddy+Deepseek-V4.1-Flash)

Windows 桌面端的网络流量监测 / 抓包工具。用 SOCKS5 或 HTTP 代理接入，也可以走内嵌的 mihomo 做
TUN 虚拟网卡全局接管；把 HTTP / HTTPS / WebSocket 流量解密后在一个原生窗口里实时展示，
可以看请求头、响应头、报文内容，也可以**改写响应**或**屏蔽某个域名**。

单文件 exe，双击即用：没有控制台窗口，不依赖外部浏览器，页面就在程序自己的窗口里。

---

## 它解决什么问题

调试一个 App 或网页时，你想知道它到底发了什么请求、返回了什么内容，还想改一改看看会怎样。
浏览器 F12 只能看自己的；`mitmproxy` 要装 Python、跑命令行；Charles / Fiddler 是外来的商业软件。

netlens 的目标是：**一个 exe 扔到 Windows 上，双击，所有流量就出现在你面前，能看能改。**

---

## 工作原理

```
              ┌─────────────── 模式一：只给单个程序配代理 ───────────────┐
目标程序 ─────┤  HTTP 代理 127.0.0.1:8080 / SOCKS5 127.0.0.1:1080      │
              └───────────────────────────┬─────────────────────────────┘
                                          │
目标程序 ──> mihomo（TUN 虚拟网卡，全量接管）──┘  ← 模式二：全局接管
             │
             ▼
        netlens：拿到真实目标（域名:端口），不靠端口号猜协议
             ├─ 嗅探首字节 0x16        → TLS  → 中间人解密 → 明文 HTTP
             ├─ 大写字母开头            → 明文 HTTP（含 WebSocket 升级）
             ├─ 配置过的 80 / 443       → 直接走对应分支
             └─ 认不出来                → 字节透传，只记流量
             │
             ├─ 命中「锁定规则」 → 不访问上游，直接返回你改过的响应
             │
             ▼
          Internet

        每个可解析的事务 ──> 记录仓库 ──> SSE 增量推送 ──> 窗口里的页面
```

---

## 功能

### 接入方式（两个入口，可同时开）

| 入口 | 默认地址 | 用途 |
|---|---|---|
| SOCKS5 | `127.0.0.1:1080` | 给 mihomo、或任何支持 SOCKS5 的程序；能拿到**原始目标域名**，不用做 DNS 反查 |
| HTTP 代理 | `127.0.0.1:8080` | 只给某一个程序配代理时最省事，支持 CONNECT 隧道 |

### TUN 虚拟网卡全局接管

- **mihomo 直接内嵌在 exe 里**（二进制 + 配置用 `go:embed` 打包），运行时释放到工作目录，
  不需要你另外准备任何文件
- 页面上一个开关就能启停；**退出程序时会自动把 mihomo 收掉**，不留孤儿进程
  （孤儿 mihomo 会挂着 TUN 路由，下次莫名其妙上不了网）
- 启动前会自动体检并明确告诉你问题在哪：
  - 当前是不是管理员权限（TUN 建虚拟网卡、改路由表必须提权）
  - 配置里的 socks5 出站端口和本程序实际监听的对不对得上（对不上就是"页面上一条都没有"）
- 配置可以在页面上直接编辑，也能一键恢复成内置默认

### 协议识别：不看端口，看内容

大多数工具按端口号猜协议，于是挂在 81 / 8000 / 8443 上的接口全部漏掉，日志里只剩一行"未解密"。
netlens 的判定顺序是：

1. 明确配置过的端口走捷径（`-http-ports` / `-tls-ports`）
2. 其余一律**嗅探连接的第一个字节**：`0x16` 是 TLS record，大写字母开头是 HTTP 方法名
3. 认不出来就字节透传，只记流量

所以非标准端口上的 HTTPS 一样能解密，明文 HTTP 也一样能解析。

### HTTPS 中间人解密

- RSA 2048 根证书 + ECDSA P-256 叶证书（签得快，且由 RSA 根签发完全合法）
- **按 SNI 决定签什么证书** —— App 用 IP 连接但带域名 SNI 时，SNI 比连接目标更准
- 按域名缓存已签发的证书，同一个域名只签一次
- 根证书一键装进 Windows「受信任的根证书颁发机构」，页面会显示当前是否已装
  （不装的话浏览器会一直报证书错误，HTTPS 看不到内容）

### WebSocket

握手之后按**帧**转发，逐帧记录方向、opcode、长度和载荷内容（按 mask 解码后展示）。
转发时载荷原样透传，所以 `permessage-deflate` 之类的扩展不会被破坏。

### 实时记录与详情

- 列表通过 SSE 实时刷新，增量按 ~120ms 合并，高频流量不会把页面打爆
- 记录有两道上限：**条数**（默认 2000）和**内存预算**（默认 128MB），超了从最老的开始淘汰
- 过滤：按关键词（域名 / 路径 / 方法 / 状态码）和分类（全部 / HTTP / WS / 透传 / 锁定 / 屏蔽）
- 详情分五个标签页：概览、请求、响应、WS 帧（WebSocket 记录才有）、原始报文

### 改响应（锁定）

选中一条记录 → 「编辑响应并锁定」→ 改状态码、响应头、响应体 → 保存。

之后**匹配到这个请求的流量不再访问上游**，一律返回你改过的那份内容，直到解除锁定。
适合"让接口返回一个我想要的假数据，看前端怎么反应"。

- 匹配条件：方法 + 主机 + 端口 + 路径
- 可选：忽略查询串（同一路径不同参数都命中）
- 可选：要求请求体逐字节相同（sha256）
- 规则面板能看到每条规则命中了几次、可以随时启停 / 编辑 / 删除
- 加 `-rules-file` 可以持久化，重启后仍然生效

### 屏蔽域名

在记录上右键，或打开详情点「屏蔽域名」→ 该域名下**所有**请求都不再出现在列表里，
只会出现在「屏蔽」那一栏。

粒度是域名而不是 URL：同一个站点有几十个接口，按路径屏蔽就得点几十次。
**只影响页面显示，流量照常转发、照常记录** —— 真断掉的话反而没法回头验证。
屏蔽名单会持久化，顶栏有独立入口可以随时取消。

### 二进制内容

图片、音视频、压缩包这类内容默认**不铺出来**，只显示类型和大小，并给两个按钮：

- **查看文本**：按 UTF-8 尽力解码后展示（二进制字节会显示成乱码，能看懂多少算多少）
- **下载**：原样保存，文件名按 `Content-Type` 猜扩展名，带 gzip 的会先解压再给

内容有独立的抓取上限（`-max-file`，默认 1MB），设成 0 就退回"只统计大小、不抓内容"。

### 中间人失败自动兜底

像 **Electron / Node 写的程序（electerm、VS Code 之类）不读 Windows 证书库**，
用的是自带那份 CA bundle，我们的伪造证书在它们眼里就是未知 CA，握手必然失败。

netlens 的应对：握手失败的主机会被**自动加入透传名单**，之后这个域名的连接直接字节透传、
不再尝试解密。名单会持久化，页面上能看、能删（删掉后下次会重新尝试解密）。

一点限制要说清楚：**失败的那一次连接救不回来**。原因是失败恰恰发生在我们已经把伪造证书
发给客户端之后，是客户端不接受才关的连接，没有"把 ClientHello 重放给真服务器"的余地。
程序重试就能通。

### 桌面应用形态

- 单文件 exe，双击打开一个原生窗口，**没有控制台窗口、也没有浏览器**
- 窗口内容是内嵌的 WebView2（Windows 11 自带运行时，**不需要打包 Chromium**，体积零增长）
- 带管理员清单：双击弹 UAC，资源管理器里图标有盾牌角标
- 程序自己的日志和 mihomo 的日志都进了页面的「日志」面板 —— 没有控制台了，
  出错时总得有地方看
- 关窗口即退出，退出时会把 mihomo 一起收掉

### 降噪

默认的日志策略是"安静的"，因为接管全部流量之后，每条请求打一屏只会把错误冲走：

- OPTIONS（CORS 预检）**不入库**（请求照常转发，只是不记录）
- 认不出协议的透传连接**不入库**，只统计数量
- 二进制内容不打十六进制
- 控制台默认只打启动信息 + 关键事件；`-v` 才打印每条请求

被过滤掉的数量会显示在页面状态栏（如「已过滤 37 条无法解析 / 12 条 OPTIONS」），
免得出现"明明在跑，页面却一条都没有"的困惑。

---

## 快速开始

1. 下载 / 编译出 `netlens.exe`，**右键「以管理员身份运行」**
   （TUN 接管和安装根证书都要提权；exe 已带管理员清单，双击就会弹 UAC）
2. 窗口打开后，顶栏点 **根证书 → 一键安装**（只需一次）
3. 点 **启动 TUN** —— 所有流量就开始进页面了

只想抓某个程序的话，不用开 TUN：把那个程序的代理指向 `127.0.0.1:8080`（HTTP）
或 `127.0.0.1:1080`（SOCKS5）即可。

---

## 命令行参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `-web` | `127.0.0.1:9600` | 控制台页面监听地址 |
| `-socks` | `127.0.0.1:1080` | SOCKS5 入口，空字符串表示不启动 |
| `-http` | `127.0.0.1:8080` | HTTP 代理入口，空字符串表示不启动 |
| `-no-window` | `false` | 不开桌面窗口，只在后台跑服务（自动化测试、排查问题时用） |
| `-install-ca` | `false` | 启动时把根证书装进系统受信任根 |
| `-mihomo-auto` | `false` | 启动时自动拉起 mihomo |
| `-mihomo-dir` | `<ca-dir>/runtime` | mihomo 工作目录（内嵌的 exe 和配置释放到这里） |
| `-web-data-dir` | `<ca-dir>/webview` | WebView2 的数据 / 缓存目录 |
| `-ca-dir` | `%APPDATA%\netlens` | 根证书、配置、名单的存放目录 |
| `-tunnel` | 空 | 不做中间人、直接透传的域名，逗号分隔（证书固定的 App 用） |
| `-http-ports` | `80` | 直接按明文 HTTP 解析的端口 |
| `-tls-ports` | `443` | 做 TLS 中间人解密的端口 |
| `-no-sniff` | `false` | 关闭未知端口的首字节嗅探 |
| `-max-body` | `512KB` | 文本 body 每条记录最多抓取的字节数 |
| `-max-file` | `1MB` | 文件类 body 每条记录最多抓取的字节数，0 = 不抓 |
| `-max-records` | `2000` | 内存里最多保留多少条记录 |
| `-max-store-mb` | `128` | 记录占用的内存上限（MB） |
| `-rules-file` | 空 | 锁定规则的持久化文件（默认只在内存里） |
| `-insecure-upstream` | `false` | 跳过上游证书校验（目标站用自签证书时才用） |
| `-show-tunnel` | `false` | 把无法解析的透传连接也记到页面上 |
| `-show-options` | `false` | 把 OPTIONS 也记到页面上 |
| `-no-browser` | `false` | 不自动打开浏览器（仅无窗口模式有效） |
| `-v` | `false` | 控制台打印每条请求 / 响应、协议判定和子进程输出 |
| `-quiet` | `false` | 控制台只打印启动横幅和错误 |
| `-no-color` | `false` | 关闭控制台彩色输出 |

---

## 构建

要求：**Go 1.24+**（实测 1.27）、Windows 10/11、WebView2 运行时（Win11 自带）。

```bash
# 1. 生成程序图标（纯 Python，不需要 PIL）
python makeicon.py app.ico

# 2. 生成 Windows 资源：应用程序清单 + 图标
#    需要 rsrc：go install github.com/akavel/rsrc@latest
rsrc -manifest app.manifest -ico app.ico -o bindata/admin/manifest.syso -arch amd64

# 3. 构建
go build -ldflags "-H=windowsgui -s -w" -o netlens.exe .

# 免提权版本（不弹 UAC，但 TUN 和自动装证书会失败）
go build -tags noadmin -ldflags "-H=windowsgui -s -w" -o netlens-noadmin.exe .
```

几个注意点：

- **`-H=windowsgui` 不能省**，否则双击还是会弹控制台窗口。可以用
  `python checkmanifest.py netlens.exe` 校验 PE 子系统、清单和图标资源是否正确
  （这几样放错了都不会报错，只会"双击弹控制台"或"图标是空白方块"）
- **`embed/mihomo.exe` 和 `embed/config.yaml` 是构建输入**，`go:embed` 不认上级目录，
  所以文件必须放在模块内。mihomo 大约 60MB，最终 exe 约 70MB
- `rsrc` 只用于生成资源文件，不进 `go.mod`；运行期依赖只有 3 个纯 Go 包
  （go-webview2 + go-winloader + golang.org/x/sys），**不需要 cgo，也不需要 C 编译器**

---

## 自测

```bash
python selftest.py     # 端到端：真起上游服务，走完整链路
node   uitest.js       # 页面：把真实 ui.html 里的脚本放进 DOM 桩里跑
python desktoptest.py  # 桌面：真开窗口，检查 WebView2 控件和 PE 属性
python memprobe.py     # 内存：灌超量数据，确认记录仓库守得住预算
```

四个脚本各有侧重，都不是"跑一下不报错"级别的：

- **selftest.py**：起真的上游（明文 HTTP / 自签 TLS / 最小 WebSocket 服务端 / 裸 TCP），
  用 Python + OpenSSL **只信任本程序的根证书**验证中间人 —— curl 在 Windows 上是
  Schannel 后端，`--cacert` 会被忽略，拿它验证中间人是白费功夫。覆盖到
  "锁定响应后把上游关掉，仍然返回改过的内容"、"中间人握手失败后重试自动透传" 这类关键行为
- **uitest.js**：不依赖任何 npm 包（自建最小 DOM 桩 + Node `vm`），跑的是**真实的
  ui.html 脚本**，能抓出拼错的 id、空引用、TDZ 之类的运行时错误。
  另有两条静态检查：页面里不允许有重复 id、日志区域必须覆盖通用 `pre` 的 `max-height`
- **desktoptest.py**：用 Win32 `EnumWindows` / `EnumChildWindows` 确认
  "真的出现了标题正确的可见窗口"，**并且窗口里嵌着 WebView2 的子控件** ——
  只验证"进程没崩"是不够的，窗口建出来但 WebView2 没挂上去照样是个白框
- **memprobe.py**：灌入远超预算的数据，确认仓库字节数和进程 RSS 都稳定在上界
  （实测 32MB 预算 → RSS ~145MB，第二轮只涨 1MB）

---

## 已知限制

都是方案本身的取舍，不是 bug：

| 限制 | 原因 | 应对 |
|---|---|---|
| HTTP/2 被降级成 HTTP/1.1 | 中间人只声明 h1，为了简化解析 | 需要 h2 得接 `golang.org/x/net/http2` |
| QUIC / HTTP3 看不到 | SOCKS5 只支持 TCP | mihomo 配置里 `udp: false`，让 App 自动回落 TCP |
| 做了证书固定的 App 连不上 | pinning 校验的是真证书 | 已自动兜底：握手失败过的主机会进透传名单；也可以手工 `-tunnel` 指定 |
| WebSocket 只能观察，不能伪造响应 | 帧流没有"响应"这个概念 | 目前只记录帧 |
| 只支持 Windows | WebView2 / Win32 都是 Windows 专有 | — |
| 无法看到无 CRL / OCSP 状态 | 伪造证书没地方吊销 | 强制吊销检查的 App 同样要走透传 |

---

## 目录结构

```
netlens/
  main.go              入口、命令行参数、启动顺序
  proxy.go             代理内核：SOCKS5/HTTP 入口、分发、转发、锁定响应
  sniff.go             协议嗅探（首字节判定）
  ca.go                根证书与动态签发（中间人用的证书链）
  socks5.go            最小 SOCKS5 服务端
  websocket.go         握手 + 帧级转发
  record.go            记录模型、有界仓库、SSE 增量推送
  rules.go             锁定规则
  blocked.go           屏蔽名单
  tunnel.go            透传名单（手工 + 自动学到）
  mihomo.go            内嵌 mihomo 的释放、启停、日志
  desktop_windows.go   WebView2 窗口
  web.go               控制台 HTTP 接口
  ui.html              单文件页面（go:embed 打包）
  app.manifest         Windows 应用程序清单（管理员权限）
  makeicon.py          生成 app.ico
  embed/               构建输入：mihomo.exe + config.yaml
  bindata/admin/       生成的资源文件（.syso）
  tools/windowcheck/   排查用的小工具：列进程的窗口和子控件类名
  selftest.py / uitest.js / desktoptest.py / memprobe.py / checkmanifest.py
```

---

## 第三方与许可证

需要特别注意的是内嵌的组件：

| 组件 | 许可证 | 说明 |
|---|---|---|
| [mihomo](https://github.com/MetaCubeX/mihomo) | **GPL-3.0**（发行版另含 LGPL-3.0 / MPL-2.0，来自它新加的依赖） | `embed/mihomo.exe` 是它的发行版二进制。**把它打包分发会牵扯到 GPL-3.0 的义务**（提供对应源码、以兼容许可证分发整体） |
| [jchv/go-webview2](https://github.com/jchv/go-webview2) | MIT | WebView2 绑定 |
| [jchv/go-winloader](https://github.com/jchv/go-winloader) | ISC | 运行时加载 DLL |
| [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) | BSD-3-Clause | — |
| WebView2Loader.dll（微软） | BSD 风格（三条款） | 由 go-webview2 内嵌，随 exe 一起分发 |
