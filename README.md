# GPU Monitor

Web 界面监控多台服务器的 NVIDIA GPU 使用情况。

## 安装

```bash
pip install -r requirements.txt
```

## 配置

复制示例配置并编辑本地 `config.json`，设置管理 Token 和服务器信息：

```bash
cp config.example.json config.json
```

`config.json` 是实际运行时读取的本地配置，包含管理 Token、服务器地址、用户名、密钥路径等敏感信息，已被 `.gitignore` 忽略；提交代码时请只提交 `config.example.json`。

```json
{
  "admin_token": "change-me",
  "monitoring": {
    "refresh_interval_seconds": 5,
    "gpu_command_total_timeout_seconds": 90,
    "gpu_operation_timeout_seconds": 150,
    "api_poll_interval_seconds": 5,
    "collector_mode": "stream",
    "collector_reconcile_interval_seconds": 2,
    "collector_retry_backoff_max_seconds": 60
  },
  "ssh": {
    "connect_timeout_seconds": 30,
    "banner_timeout_seconds": 45,
    "auth_timeout_seconds": 45,
    "connection_total_timeout_seconds": 120,
    "channel_open_timeout_seconds": 60,
    "reused_channel_open_timeout_seconds": 20,
    "command_idle_timeout_seconds": 60,
    "keepalive_interval_seconds": 15,
    "retry_count": 1,
    "retry_backoff_base_seconds": 2,
    "retry_backoff_max_seconds": 4,
    "retry_jitter_seconds": 2,
    "connect_jitter_seconds": 1.5
  },
  "servers": [
    {
      "name": "Server 1",
      "host": "192.168.1.100",
      "port": 22,
      "username": "your_username",
      "key_file": "~/.ssh/id_rsa",
      "accept_unknown_host": false
    }
  ]
}
```

默认 `collector_mode=stream`：每台服务器拥有独立采集线程、专用 SSH Transport 和一个长生命周期 Channel。本地按 `refresh_interval_seconds` 为该服务器安排下一次采样；若上一次尚未完成则不并发、不补发，完成后立即进入下一次。慢服务器不会阻塞其他服务器。远端只运行随 SSH Channel 存活的 shell，不安装服务、不写文件，断线后由 sshd 回收。stream 启动时会查询并缓存一次 GPU 拓扑；之后每轮只调用一次 `nvidia-smi -q -d MEMORY,UTILIZATION,PIDS`，并在远端将约 21 KB 的人类可读输出压缩回现有 GPU/APPS/PS CSV，通常只传输约 0.6–1 KB。输出缺字段或 GPU 拓扑变化时整轮失败并通过重连刷新拓扑，不会发布部分数据。`poll` 模式保留独立调度但每次重新执行命令，`batch` 模式保留旧的整批查询逻辑（切换 `batch` 后需重启进程）。

`gpu_command_total_timeout_seconds` 是单次远端采样的子预算，`gpu_operation_timeout_seconds` 是包含排队、建连和 Channel 启动在内的单服务器预算；超时后的异步资源清理最多允许 1 秒共享宽限期。采集器断线按指数退避，最大值由 `collector_retry_backoff_max_seconds` 控制。前端通过 `api_poll_interval_seconds` 读取逐服务器更新的内存缓存，页面显示的是最新样本时间而不是轮询时间。

SSH timeout 均以秒为单位：建连、banner、认证、Channel 打开和命令空闲等待分别配置。只读查询遇到瞬态传输错误时最多安全重连一次，并带随机退避；用户配置、撤权和删账号等写操作在命令可能已经发出后不会自动重放。单台服务器可通过自己的 `ssh` 对象覆盖全局 SSH 参数。

**安全说明：**
- `admin_token`: 执行用户授权配置时需要在前端弹窗输入的管理 Token，请在本地 `config.json` 中改成强随机字符串
- `accept_unknown_host`: 是否自动接受未知主机密钥（默认 false）
  - `false`: 使用系统 known_hosts 验证主机密钥（推荐，更安全）
  - `true`: 自动接受新主机密钥（仅用于测试环境）
- 生产环境请预先配置 SSH known_hosts 或手动连接一次服务器以添加主机密钥
- API 端点不再暴露敏感配置信息（host、username、key_file）

## 运行

```bash
# 生产环境
python app.py

# 开发环境（启用调试）
FLASK_DEBUG=true python app.py
```

访问 http://localhost:5000 查看监控界面。

## 功能

- 实时显示 GPU 利用率和显存使用情况
- 显示占用 GPU 的进程及用户
- 每服务器独立常驻采集（默认目标周期 5 秒）
- 支持多服务器监控
- 专用 SSH 常驻 Channel、连接复用、保活、限流和单服务器独立重连
- 前端 XSS 防护
