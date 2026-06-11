# CC Switch（隐私过滤版）

## 致谢

- [Linux.do](https://linux.do)
- [packyme/privacy-filter](https://github.com/packyme/privacy-filter) —— 提供本地隐私过滤引擎

---

基于 [cc-switch](https://github.com/farion1231/cc-switch) 的修改版，新增**本地隐私过滤**能力：在代理转发请求到上游 API 之前，自动检测并脱敏请求中的敏感信息（PII 与密钥）。过滤引擎来自 [packyme/privacy-filter](https://github.com/packyme/privacy-filter)，全部处理在本机完成，不依赖任何外部服务。

## 下载

前往 [Releases](../../releases) 下载：

| 文件 | 平台 |
|---|---|
| `CC Switch_x.x.x_aarch64.dmg` | macOS（Apple Silicon）|
| `CC Switch_x.x.x_x64-setup.exe` | Windows x64 |

> macOS 首次打开如提示"已损坏"，执行 `xattr -cr "/Applications/CC Switch.app"` 后重新打开。
> Windows 首次运行如遇 SmartScreen 警告，点"更多信息 → 仍要运行"。

## 隐私过滤使用方法

### 工作原理

```
AI CLI 工具 → CC Switch 本地代理 → [隐私过滤] → 上游 API
                      ↓
              privacy-filter 子进程
            （随应用自动启动/停止，默认端口 18088，仅监听本机）
```

请求体中的文本字段在转发前被批量脱敏，命中的内容替换为占位符后再发往上游。过滤为**尽力而为**：过滤服务不可用时按原文转发，不阻断 AI 请求。

### 检测的敏感信息类型

| 类型 | 占位符 |
|---|---|
| 邮箱地址 | `[邮箱]` |
| 手机号（中国大陆）| `[电话]` |
| 身份证号 | `[身份证]` |
| 银行卡号 | `[银行卡]` |
| IP 地址 | `[IP]` |
| API 密钥 / 凭证 / 高熵 Token | `[密钥]` |

支持 Claude（Messages）、Codex（OpenAI Responses / Chat Completions）、Gemini 三类请求格式。

### 开启步骤

1. **开启应用路由**：在主界面为要使用的应用（Claude / Codex / Gemini）打开路由开关——隐私过滤只对经过本地代理的流量生效
2. 打开 **设置 → 隐私** 标签页，开启 **启用隐私过滤** 并保存，服务自动启动
3. 状态徽标显示 **运行中** 即生效
4. 在"测试过滤功能"输入示例验证：

   ```
   输入：我的邮箱是 contact@example.com，手机号是 13800138000
   结果：我的邮箱是 [邮箱]，手机号是 [电话]
   ```

### 验证过滤是否生效

查看应用日志（`~/.cc-switch/logs/cc-switch.log`）：

```bash
grep "Privacy filter" ~/.cc-switch/logs/cc-switch.log | tail
```

出现 `Privacy filter: N sensitive item(s) redacted` 即表示脱敏已执行。

> ⚠️ 注意：用抓包工具（如 Proxyman）看到 CLI → 本地代理这一跳是明文属正常现象，脱敏发生在本地代理 → 上游的转发环节。

### 常见问题

- **过滤不生效**：先确认对应应用的**路由开关已开启**（CLI 配置的 `base_url` 应指向本地代理地址），再确认隐私过滤状态为"运行中"
- **服务无法启动**：检查 18088 端口占用（`lsof -i :18088`），可在设置页修改服务端口
- **更多细节**：见 [隐私过滤功能指南](docs/guides/privacy-filter-guide-zh.md)

## 从源码构建

详见 [隐私过滤功能指南 - 构建说明](docs/guides/privacy-filter-guide-zh.md#构建说明开发者)。

## License

MIT（与上游一致）
