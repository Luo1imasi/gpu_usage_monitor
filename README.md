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
- 自动刷新（默认 5 秒）
- 支持多服务器监控
- SSH 连接池复用，提升性能
- 前端 XSS 防护
