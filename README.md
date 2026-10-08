# GPU Monitor

基于 Flask 和 SSH 的多服务器 NVIDIA GPU 监控与用户访问管理工具。

## 功能

- 展示 GPU 利用率、显存占用、进程和用户
- 按服务器独立采集，慢服务器互不阻塞
- 复用 SSH 连接，支持保活、限流、超时和重试
- 管理远端用户、SSH 公钥和 sudo 权限
- 检查用户在各服务器上的访问状态
- 展示 `/home` 文件系统和各用户目录占用
- 对管理接口使用管理员 Token 鉴权
- 使用已登记 SSH 公钥登录网站和 API；私钥仅在浏览器内用于签名

## 安装

```bash
pip install -r requirements.txt
cp config.example.json config.json
```

被监控服务器需要支持 SSH 并安装 NVIDIA 驱动。用户管理功能还需要远端 Python 3 和免交互 `sudo`。

## 配置

复制 `config.example.json` 为 `config.json`，通常只需要设置 `admin_token` 和 `servers`。示例文件仅保留常用项；未列出的采集、超时和重试参数继续使用程序内置默认值，旧配置中的高级参数仍然兼容。

常用可选项：

- `monitoring.refresh_interval_seconds`：GPU 采样与页面更新周期；示例为 2 秒。
- `monitoring.storage_refresh_interval_seconds`：存储采集周期，默认 300 秒。
- `monitoring.storage_user_min_size_mb`：用户目录显示阈值，默认 100 MiB。
- `monitoring.collector_mode`：GPU 采集模式，默认 `stream`。
- `ssh`：全局 SSH 超时和重试覆盖；也可在单台服务器的 `ssh` 中覆盖。
- `servers[].accept_unknown_host`：是否接受未知主机密钥，默认 `false`。

页面直接按 GPU 采样周期读取最新状态，不再单独配置缓存轮询周期。

`config.json` 和 `user.txt` 包含本地运行数据，均不应提交到版本库。

### 采集模式

- `stream`：每台服务器使用独立线程和长生命周期 SSH Channel，按采样周期请求 GPU 数据。
- `poll`：每台服务器独立调度，每轮执行一次采集命令。
- `batch`：按批次并发查询全部服务器；切换到或退出该模式需要重启进程。

远端采集通过临时 shell 执行，不安装服务或写入程序文件。只读查询可在瞬态传输错误后重连一次；远端写操作使用保守重试策略，避免重复执行结果不确定的命令。

### 访问与 Key 管理

- 新增 SSH Key 只会先写入本地 `user.txt`；在权限矩阵中选择对应用户和服务器并执行配置后，Key 才会同步到远端。
- 权限矩阵会区分全部 Key 已同步、部分 Key 已同步和缺少 Key；部分同步的单元格可以再次配置以补齐新 Key。
- 在权限矩阵中选择一个或多个“用户 × 服务器”单元格并点击“取消选中权限”，会只从所选服务器删除本项目登记的该用户全部 Key。本地 Key 和其他服务器权限会保留，之后仍可重新配置；该操作不会清空未登记的 Key、锁定账号或终止现有会话。
- “删 Key”可以选择一把或多把 Key，并从全部已配置服务器删除。只有所有远端操作都成功后，程序才会删除本地 Key；删掉最后一把 Key 时，`user.txt` 会保留仅含用户名的 0-Key 账户记录，权限矩阵中的“删账号”入口仍可继续使用。
- 删除 Key 不会锁定账号、终止现有会话或移除密码登录能力；需要彻底删除远端账号时使用“删账号”。删账号会尝试覆盖全部配置服务器，任一远端失败时保留本地记录以便重试。
- SSH Key 权限粒度是服务器，而不是同一服务器内的单张物理 GPU；单卡隔离需要使用容器、调度器或 cgroup 等 GPU 级控制。
- 如果多台服务器通过 NFS 等方式共享同一个 home/`authorized_keys` 文件，在其中一台服务器修改该文件也会影响其他共享服务器，不能视为彼此独立的权限边界。

服务器卡片内的存储项展示 `/home` 所在文件系统的总量、已用和可用空间；用户占用来自 UID 不小于 1000、主目录位于 `/home` 下的账号目录，按 `du -skx` 的已分配空间统计。`monitoring.storage_user_min_size_mb` 控制纳入统计的最小占用，默认为 100 MiB；仅过滤严格低于阈值且已成功测量的用户，达到阈值的用户仍会显示。无法测量的用户会保留并标记为部分可用，完整统计需要免交互 `sudo`。

## 运行

```bash
python3 app.py
```

开发模式：

```bash
FLASK_DEBUG=true python3 app.py
```

访问 <http://localhost:5000>。

### 网站登录

所有监控页面和 API 均要求先登录。在登录页选择与 `user.txt` 中已登记公钥对应的 SSH 私钥文件，若私钥有密码则输入密码。支持 RSA、Ed25519 和 ECDSA（nistp256/384/521），支持 OpenSSH 私钥及常见 PEM 私钥，包括密码保护的私钥。不支持 PuTTY PPK、硬件密钥及 SSH 证书。

浏览器把文件交给禁止联网的本地 Worker，解析私钥并签署一次性登录挑战。网络请求只发送 `key_id`、挑战编号和签名，不上传私钥文件或私钥密码，不使用 localStorage/sessionStorage 保存它们。签名结束或失败后终止 Worker。由于网页代码需要读取私钥，仍需信任网站提供的代码；服务器若遭入侵并替换前端代码，纯 Web 方案无法保证私钥不被窃取。建议为本网站使用专用 SSH 密钥。

生产访问必须使用 HTTPS，本机可使用 `http://localhost:5000`。认证 Cookie 使用 Secure、HttpOnly 和 SameSite=Strict；普通局域网 HTTP 地址无法登录。若部署在一层可信 HTTPS 反向代理之后，设置 `GPU_MONITOR_TRUST_PROXY=1`，并让代理覆盖 `X-Forwarded-For` 和 `X-Forwarded-Proto`、保留原始 Host，同时禁止外部直接连接 Flask。不要在 Flask 可被直接公网访问时开启该选项。

会话有效期为 8 小时；登录挑战有效期为 60 秒且只能使用一次。删除已登记的公钥后，对应会话立即无法访问；无 Key 用户不能登录，同一公钥若绑定多个不同用户名则拒绝登录。登录只赋予网站访问权，管理接口仍额外要求管理员 Token。首次使用前需要由可信管理员在 `user.txt` 登记公钥，文件格式为 `用户名 ssh-ed25519 AAAA...`，每把公钥一行。

认证状态保存在本地 `auth.sqlite3`，可通过 `GPU_MONITOR_AUTH_DATABASE` 指定位置；同一部署的多个 Flask worker 必须共用该文件。需要撤销全部会话时，停止应用后删除此数据库，再启动应用。浏览器中的 API 请求自动使用登录 Cookie；独立 API 客户端也需完成挑战签名并保存 Cookie。所有 POST/DELETE 等修改请求必须携带 `X-Monitor-Request: 1`，浏览器请求还会校验 Origin。

在可信的本机 Nginx HTTPS 代理之后启动时使用 `GPU_MONITOR_TRUST_PROXY=1 python3 app.py`。此模式下程序只监听 `127.0.0.1:5000`，由 Nginx 提供对外访问；端口仍为 5000。遗漏该环境变量会导致 HTTPS 登录请求因 `invalid_origin` 被拒绝。

浏览器签名依赖已打包到仓库内，无需运行时访问 CDN。修改签名代码后重新生成文件：

```bash
npm ci --ignore-scripts
npm run build:login
npm run build:ui
```

端到端登录测试（需要本机 Chrome、Node.js 和 `ssh-keygen`，可用 `CHROME_PATH` 指定 Chrome 路径）：

```bash
npm run test:login
```

## 安全

- 为 `admin_token` 设置强随机值。
- `accept_unknown_host=false` 时使用系统 `known_hosts` 验证服务器主机密钥。
- 生产环境应预先写入可信主机密钥。
- 服务器列表 API 响应仅包含服务器名称。

## 核心模块

```text
app.py                         # 服务入口
gpu_monitor/
├── config.py                  # 配置加载与参数约束
├── ssh.py                     # SSH 连接和命令执行
├── storage.py                 # /home 存储采集与缓存
├── user_store.py              # 用户与 SSH 公钥存储
├── access/
│   ├── remote_commands.py     # 远端用户管理命令
│   └── service.py             # 授权与访问矩阵服务
├── gpu/
│   ├── commands.py            # GPU 采集命令
│   ├── parsing.py             # 输出与帧协议解析
│   ├── state.py               # GPU 状态缓存
│   └── collector.py           # 采集器与调度
├── web.py                     # Flask 应用与路由
└── runtime.py                 # 后台任务与资源关闭
```

## 测试

```bash
python3 -m unittest discover -v
```
