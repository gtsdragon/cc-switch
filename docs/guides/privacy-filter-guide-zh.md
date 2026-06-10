# 隐私过滤功能指南

CC Switch 内置可选的隐私过滤能力：在本地代理将请求转发到上游 API 之前，
自动检测并脱敏请求中的敏感信息（PII 与密钥/凭证）。全部处理在本机完成，
不依赖任何外部服务。

## 工作原理

```
AI CLI 工具 → CC Switch 代理 → [隐私过滤] → 上游 API
                    ↓
            privacy-filter 子进程
            (HTTP 服务，由 CC Switch 自动管理)
```

- 过滤引擎来自 [privacy-filter](https://github.com/your-org/privacy-filter) 项目
  （Go 实现：正则 PII 检测 + gitleaks 规则集密钥检测 + 高熵兜底），
  以独立子进程方式随 CC Switch 启动/停止。
- 启用后，代理在转发前提取请求体中的文本字段，批量调用本地过滤服务，
  将命中的内容替换为占位符后再转发。
- **尽力而为（best-effort）**：过滤服务不可用时记录警告并按原文转发，
  不会阻断 AI 请求。

## 覆盖的请求字段

| API | 过滤字段 |
|---|---|
| Claude Messages | `system`、`messages[].content`（含 `tool_result` 嵌套内容） |
| OpenAI Chat Completions | `messages[].content` |
| OpenAI Responses（Codex CLI） | `instructions`、`input`（含 `function_call_output.output`） |
| Gemini | `systemInstruction`、`contents[].parts[].text` |

## 检测的敏感信息类型

| 类型 | 占位符 |
|---|---|
| 邮箱地址 | `[邮箱]` |
| 手机号（中国大陆） | `[电话]` |
| 身份证号 | `[身份证]` |
| 银行卡号 | `[银行卡]` |
| IP 地址 | `[IP]` |
| API 密钥 / 凭证 / 上下文口令 / 高熵 Token | `[密钥]` |

密钥检测默认加载打包的 gitleaks 规则集（`resources/gitleaks.toml`）；
规则文件缺失时回退到内置兜底规则。

## 使用方法

1. 打开 **设置 → 隐私** 标签页
2. 打开 **启用隐私过滤** 开关并保存，服务自动启动（默认端口 18088）
3. 状态徽标显示 **运行中** 即生效
4. 可在"测试过滤功能"区域输入示例文本验证效果，例如：

   ```
   我的邮箱是 contact@example.com，手机号是 13800138000
   ```

   过滤结果：

   ```
   我的邮箱是 [邮箱]，手机号是 [电话]
   ```

### 修改端口

默认端口 18088 被占用时，在设置页修改"服务端口"（≥1024）并保存，
服务会自动以新端口重启。代理转发与服务管理共用该配置。

## 构建说明（开发者）

privacy-filter 二进制不入库，构建前需先生成并放入 `src-tauri/resources/`：

```bash
# 默认构建当前平台，并复制 gitleaks.toml
./scripts/build-privacy-filter.sh /path/to/privacy-filter

# 交叉编译多平台
TARGETS="darwin/arm64 darwin/amd64 linux/amd64 windows/amd64" \
  ./scripts/build-privacy-filter.sh /path/to/privacy-filter
```

产物命名遵循 Go 风格：`privacy-filter-<GOOS>-<GOARCH>[.exe]`
（如 `privacy-filter-darwin-arm64`）。Rust 端会把 `std::env::consts`
的平台名映射到该命名（macos→darwin、aarch64→arm64、x86_64→amd64）。

随后正常构建即可，`tauri.conf.json` 的 `bundle.resources` 通过
glob（`resources/privacy-filter-*`）打包当前平台的二进制：

```bash
pnpm install
pnpm tauri build
```

## 实现要点

- **服务管理**：`src-tauri/src/privacy_filter.rs` —— 子进程生命周期、
  健康检查（启动后轮询就绪）、HTTP 客户端（直连回环地址，不走全局出站代理）
- **代理集成**：`src-tauri/src/proxy/privacy_filter.rs` —— 文本提取/回填与降级逻辑
- **Tauri 命令**：`src-tauri/src/commands/privacy_filter.rs` —— 启停/状态/测试/配置
- **退出清理**：`cleanup_before_exit` 显式停止子进程（`std::process::exit` 不走 Drop）
- **上游 API 契约**：`GET /health` 返回 `{"status":"ok",...}`；
  `POST /redact/batch` 返回**裸数组**（详见 `privacy_filter.rs` 模块注释）

## 故障排查

- **服务无法启动**：检查端口占用（`lsof -i :18088`）；确认
  `resources/privacy-filter-darwin-arm64`（或对应平台文件）存在且可执行
- **状态显示"服务异常"**：关闭再重新开启过滤开关；查看应用日志
- **过滤不生效**：确认开关已开启且状态为"运行中"，用测试功能验证；
  查看代理日志中的 `Privacy filter: N sensitive item(s) redacted` 记录

## 性能与隐私

- 处理为毫秒级（批量接口一次往返），客户端超时 1s，超时即降级原文转发
- 所有处理在本机回环地址完成，不发送至外部服务器，不存储任何内容
