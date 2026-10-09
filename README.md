# Claude Local Clean

一个只在 Windows 本机运行的 Claude Code / Claude Desktop 清理控制台。它不连接远程服务器，不包含 SSH、ADB、虚拟机或任何预设设备信息，也不会上传扫描结果。

> 本项目与 Anthropic 无关联。它会删除本机文件并可修改 Windows `MachineGuid`；请先阅读下面的行为说明。

## 功能

### 环境清理

控制台提供四种本机模式：

| 模式 | 会做什么 | 明确保留 |
| --- | --- | --- |
| 设备关联清理 | 从 `~/.claude.json` 删除 Claude 自有的设备关联字段；删除 `~/.claude/telemetry`、`statsig` 和 `stats-cache.json` | 登录凭据、项目对话、`history.jsonl`、`session-env`、`file-history`、`backups` |
| 设备关联与审计记录 | 包含上一项，并删除当前 Claude Desktop 数据根中的 `audit.jsonl` | 普通 Claude Code 项目对话、文件回退数据和历史保全副本 |
| 完整本机清理 | 再删除可重建的粘贴、shell 快照、调试缓存，以及 allowlist 内的 Desktop 缓存/设备注册残留 | 登录、账号资料、sessions、工作资产 |
| 隐私加固 | 合并隐私相关环境变量到 `~/.claude/settings.json`，设置 `autoUpdates=false`，并合并 Desktop 托管隐私配置 | 已有主题、插件、hooks 和其他 env 配置 |

Desktop 残留清理只处理明确列出的名称：`ant-device-registry.json`、`ant-did`、`sentry`、`Crashpad`、`Code Cache`、`logs`，以及 `Claude-3p/configLibrary/_meta.json.bak`。

内置 Claude Code 二进制修改采用严格 fail-closed 规则：当前只识别 `2.1.281` 的已知原始/已处理 SHA-256、固定文件长度和内容结构。检测到更高版本时，其他常规清理会继续完成，控制台会弹窗提示自行扫描新版文件后再进行深度清理；新版二进制本身不会被修改。同版本哈希异常、内容结构漂移或写后校验失败仍会标记为部分完成。处理为等长、原位替换，不创建持久备份。

### Claude 账号

账号扫描只读取本机 Claude 目录，并区分两种动作：

- **退役旧账号**：只能选择扫描到且不属于当前登录账号的 UUID。删除该旧 UUID 的本地会话目录和已知映射；当前登录、OAuth 凭据和工作资产受到保护。
- **清空全部账号与登录层**：仅适用于已经从所有 Claude 账号退出的状态。会清理本机 Claude 账号 UUID、组织关联、登录存储，以及精确匹配 `Anthropic API` 或 `Claude Code` 的 Windows 凭据项；项目、skills、settings、file-history、sessions、session-env 和 backups 保留。

两个动作都要求 Claude 与 Claude Code 完全退出。解析失败、进程检测失败或路径越界会拒绝执行；部分失败会报告为可重试状态，不会伪装成完成。

### Machine ID

读取或修改本机：

```text
HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
```

输入可以是标准 GUID，也可以是 32 位十六进制字符串。写入需要 Windows 管理员授权，写后会立即重新读取校验，并提示重启。此功能不会修改远程设备或 Linux `/etc/machine-id`。

## 运行

要求：

- Windows 10 或 Windows 11
- Python 3.11 或更高版本
- Claude 在执行清理或账号操作前完全退出

下载仓库后双击：

```text
clean.bat
```

控制台只监听 `127.0.0.1:8190`，随后在默认浏览器打开页面。保持黑色终端窗口开启；可按 `Ctrl+C`、关闭该窗口，或运行 `stop.bat` 停止服务。

也可以手动启动：

```powershell
python server.py
```

## 本地安全边界

- HTTP 服务固定绑定 IPv4 loopback，不接受局域网或公网连接。
- 启动和停止脚本会验证固定服务身份与 API 协议版本，不会接管同端口的其他本机服务。
- 修改请求必须携带每次启动随机生成的 CSRF token，并使用精确确认词。
- 删除和覆盖前会拒绝 symlink、junction 等重解析目标，避免 allowlist 路径被重定向。
- 不包含遥测、网络客户端、远程设备配置、凭据、个人路径或运行日志。
- 不自动备份清理目标；JSON 更新采用临时文件加原子替换，账号 JSON 批量写入失败时会尝试回滚本轮写入。
- 本工具只能处理本机状态，不能删除服务端记录，也不保证改变任何服务端判断或账号状态。

## 测试

```powershell
python -m unittest -v
ruff check .
```

测试覆盖账号保护/退役/全清、路径边界、部分失败重试、Desktop allowlist、已知二进制内容校验、CLI 模式和本机 HTTP API 的令牌边界。

## License

[MIT](LICENSE)
