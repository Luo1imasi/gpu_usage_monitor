# GPU Monitor

Web 界面监控多台服务器的 NVIDIA GPU 使用情况。

## 安装

```bash
pip install -r requirements.txt
```

## 配置

编辑 `config.json`，添加你的服务器信息：

```json
{
  "servers": [
    {
      "name": "Server 1",
      "host": "192.168.1.100",
      "port": 22,
      "username": "your_username",
      "key_file": "~/.ssh/id_rsa",
      "accept_unknown_host": false
    }
  ],
  "refresh_interval": 5
}
```

**安全说明：**
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
- 自动刷新（默认 5 秒）
- 支持多服务器监控
- SSH 连接池复用，提升性能
- 前端 XSS 防护