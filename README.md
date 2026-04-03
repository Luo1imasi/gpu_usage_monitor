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
      "key_file": "~/.ssh/id_rsa"
    }
  ],
  "refresh_interval": 5
}
```

确保 SSH 密钥已配置，可以免密登录到目标服务器。

## 运行

```bash
python app.py
```

访问 http://localhost:5000 查看监控界面。

## 功能

- 实时显示 GPU 利用率和显存使用情况
- 显示占用 GPU 的进程及用户
- 自动刷新（默认 5 秒）
- 支持多服务器监控