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

## 安装

```bash
pip install -r requirements.txt
cp config.example.json config.json
```

被监控服务器需要支持 SSH 并安装 NVIDIA 驱动。用户管理功能还需要远端 Python 3 和免交互 `sudo`。

## 配置

复制 `config.example.json` 为 `config.json`，通常只需要设置 `admin_token` 和 `servers`。示例文件仅保留常用项；未列出的采集、超时和重试参数继续使用程序内置默认值，旧配置中的高级参数仍然兼容。

常用可选项：

- `monitoring.storage_refresh_interval_seconds`：存储采集周期，默认 300 秒。
- `monitoring.storage_user_min_size_mb`：用户目录显示阈值，默认 100 MiB。
- `monitoring.collector_mode`：GPU 采集模式，默认 `stream`。
- `ssh`：全局 SSH 超时和重试覆盖；也可在单台服务器的 `ssh` 中覆盖。
- `servers[].accept_unknown_host`：是否接受未知主机密钥，默认 `false`。

`config.json` 和 `user.txt` 包含本地运行数据，均不应提交到版本库。

### 采集模式

- `stream`：每台服务器使用独立线程和长生命周期 SSH Channel，按采样周期请求 GPU 数据。
- `poll`：每台服务器独立调度，每轮执行一次采集命令。
- `batch`：按批次并发查询全部服务器；切换到或退出该模式需要重启进程。

远端采集通过临时 shell 执行，不安装服务或写入程序文件。只读查询可在瞬态传输错误后重连一次；远端写操作使用保守重试策略，避免重复执行结果不确定的命令。

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
