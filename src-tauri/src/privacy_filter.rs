//! 隐私过滤模块
//!
//! 管理内嵌的 privacy-filter HTTP 服务，在 AI 请求发送前过滤敏感信息。
//!
//! ## 功能
//! - 子进程生命周期管理（启动/停止/健康等待）
//! - HTTP 客户端封装（调用 /redact、/redact/batch API）
//! - 请求体文本字段的提取与回填
//!
//! ## 架构
//! ```text
//! AI 工具 → cc-switch proxy → [privacy-filter] → upstream API
//!                   ↓
//!           PrivacyFilterService
//!           (管理子进程 + HTTP 客户端)
//! ```
//!
//! ## 上游 API 契约（privacy-filter internal/httpapi）
//! - `GET /health` → `{"status":"ok","gitleaks_rules":N,"skipped_rules":M}`
//! - `POST /redact {"text":...}` → `{"redacted":...,"hit":bool,"count":N,...}`
//! - `POST /redact/batch {"texts":[...]}` → 裸数组 `[{...},{...}]`（无包裹对象）

use crate::error::AppError;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// 默认监听端口（避免与 privacy-filter 默认的 8088 及常见服务冲突）
pub const DEFAULT_PORT: u16 = 18088;

/// 清理占用指定端口但已失管的 privacy-filter 子进程（孤儿进程）。
///
/// ## 背景
/// app 异常退出时（崩溃、被强杀、断电，`cleanup_before_exit` 不执行），
/// privacy-filter 子进程会残留并成为孤儿进程（父进程为 PID 1）继续占用端口。
/// 之后每次 `start()` spawn 的新进程会因端口被占而绑定失败、立即退出；但
/// `wait_until_healthy()` 的 HTTP 健康检查会命中 **旧孤儿进程** 的响应而误判
/// "健康"，同时 `is_running()` 检查自己 spawn 的进程发现已死——UI 因此显示
/// "已停止" 而脱敏其实仍由孤儿进程在提供，状态失真。
///
/// 因此在 spawn 前先探测端口占用，仅当占用者确实是残留的 privacy-filter
/// 进程时将其终止，为本次启动让出端口。非 privacy-filter 的第三方占用不主动
/// 杀死（避免误伤），交由后续启动失败路径报错处理。
fn cleanup_orphaned_on_port(port: u16) {
    for pid in pids_listening_on_port(port) {
        if pid_is_privacy_filter(pid) {
            log::warn!(
                "[PrivacyFilter] Killing orphaned privacy-filter process (PID {}) occupying port {}",
                pid,
                port
            );
            #[cfg(target_os = "windows")]
            let _ = std::process::Command::new("taskkill")
                .args(["/F", "/PID", &pid.to_string()])
                .status();
            #[cfg(not(target_os = "windows"))]
            let _ = std::process::Command::new("kill")
                .args(["-9", &pid.to_string()])
                .status();
        }
    }
}

/// 列出监听指定 TCP 端口的进程 PID。
/// - macOS/Linux: `lsof -ti tcp:<port>`（仅含监听该端口的进程）
/// - Windows: `netstat -ano` 解析得到
fn pids_listening_on_port(port: u16) -> Vec<u32> {
    #[cfg(target_os = "windows")]
    {
        let Ok(output) = std::process::Command::new("netstat")
            .args(["-ano", "-p", "tcp"])
            .output()
        else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&output.stdout);
        let wanted = format!(":{port}");
        let mut pids = Vec::new();
        for line in text.lines() {
            // 形如:  TCP    0.0.0.0:18088  0.0.0.0:0  LISTENING  12345
            if line.contains(&wanted) && line.contains("LISTENING") {
                if let Some(pid) = line.split_whitespace().last() {
                    if let Ok(p) = pid.parse::<u32>() {
                        pids.push(p);
                    }
                }
            }
        }
        pids
    }
    #[cfg(not(target_os = "windows"))]
    {
        // lsof -ti tcp:<port> -sTCP:LISTEN  → 每行一个监听该端口的 PID
        let Ok(output) = std::process::Command::new("lsof")
            .args([
                "-ti",
                &format!("tcp:{port}"),
                "-sTCP:LISTEN",
            ])
            .output()
        else {
            return Vec::new();
        };
        let text = String::from_utf8_lossy(&output.stdout);
        text.lines()
            .filter_map(|l| l.trim().parse::<u32>().ok())
            .collect()
    }
}

/// 判断指定 PID 的进程名是否属于 privacy-filter 二进制。
#[cfg(target_os = "windows")]
fn pid_is_privacy_filter(pid: u32) -> bool {
    let Ok(out) = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/FO", "CSV", "/NH"])
        .output()
    else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout).to_lowercase().contains("privacy-filter")
}

/// 判断指定 PID 的进程名是否属于 privacy-filter 二进制。
#[cfg(not(target_os = "windows"))]
fn pid_is_privacy_filter(pid: u32) -> bool {
    let Ok(out) = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
    else {
        return false;
    };
    String::from_utf8_lossy(&out.stdout).to_lowercase().contains("privacy-filter")
}

/// HTTP 客户端超时时间。
/// localhost 往返通常 <5ms；放宽到 1s 以容忍大请求体（长对话历史可达数百 KB）。
const REQUEST_TIMEOUT_MS: u64 = 1000;

/// 启动后等待服务就绪的轮询次数与间隔
const STARTUP_PROBE_ATTEMPTS: u32 = 10;
const STARTUP_PROBE_INTERVAL_MS: u64 = 200;

/// 过滤请求
#[derive(Debug, Serialize)]
struct RedactRequest {
    text: String,
}

/// 过滤响应（与 Go 端 filter.Result + elapsed_ms 对应，未知字段忽略）
#[derive(Debug, Deserialize)]
pub struct RedactResponse {
    pub redacted: String,
    #[serde(default)]
    pub hit: bool,
    #[serde(default)]
    pub count: usize,
}

/// 健康检查响应
#[derive(Debug, Deserialize)]
struct HealthResponse {
    status: String,
}

/// 隐私过滤服务状态
#[derive(Debug, Clone, Serialize)]
pub struct PrivacyFilterStatus {
    pub running: bool,
    pub port: u16,
    pub healthy: bool,
    pub error: Option<String>,
}

/// 共享 HTTP 客户端。
///
/// 不复用 `proxy::http_client` 的全局客户端：那个客户端会应用用户配置的
/// 出站代理，而这里访问的是本机回环地址，必须直连且使用更短的超时。
pub fn shared_client() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .timeout(Duration::from_millis(REQUEST_TIMEOUT_MS))
            .no_proxy()
            .build()
            .expect("Failed to create privacy filter HTTP client")
    })
}

/// 调用 privacy-filter 的批量过滤接口。
///
/// 上游返回裸数组（非 `{"results":[...]}` 包裹）。
pub async fn redact_batch(port: u16, texts: &[String]) -> Result<Vec<RedactResponse>, AppError> {
    let url = format!("http://127.0.0.1:{}/redact/batch", port);
    let request_body = serde_json::json!({ "texts": texts });

    let response = shared_client()
        .post(&url)
        .json(&request_body)
        .send()
        .await
        .map_err(|e| AppError::Config(format!("Privacy filter batch request failed: {}", e)))?;

    if !response.status().is_success() {
        return Err(AppError::Config(format!(
            "Privacy filter returned status: {}",
            response.status()
        )));
    }

    response
        .json::<Vec<RedactResponse>>()
        .await
        .map_err(|e| AppError::Config(format!("Failed to parse batch response: {}", e)))
}

/// 隐私过滤服务
///
/// 由 `commands::PrivacyFilterState` 持有，全局唯一。
pub struct PrivacyFilterService {
    /// 子进程句柄
    process: Mutex<Option<Child>>,
    /// 监听端口
    port: u16,
    /// Tauri 资源目录（用于定位打包的二进制与规则文件）
    resource_dir: Option<PathBuf>,
}

impl PrivacyFilterService {
    /// 创建服务实例
    ///
    /// `resource_dir` 传入 `app.path().resource_dir()` 的结果；
    /// 为 `None` 时回退到可执行文件旁的 `resources/` 目录查找。
    pub fn new(port: u16, resource_dir: Option<PathBuf>) -> Self {
        Self {
            process: Mutex::new(None),
            port,
            resource_dir,
        }
    }

    /// Go 构建产物的命名习惯：GOOS/GOARCH（darwin/arm64），
    /// 与 Rust 的 `std::env::consts`（macos/aarch64）不同，需要映射。
    fn go_platform_suffix() -> (&'static str, &'static str) {
        let os = match std::env::consts::OS {
            "macos" => "darwin",
            other => other,
        };
        let arch = match std::env::consts::ARCH {
            "aarch64" => "arm64",
            "x86_64" => "amd64",
            other => other,
        };
        (os, arch)
    }

    /// 候选资源根目录（按优先级）：Tauri 资源目录 → 可执行文件旁 → macOS bundle Resources
    fn candidate_resource_roots(&self) -> Vec<PathBuf> {
        let mut roots = Vec::new();

        if let Some(dir) = &self.resource_dir {
            roots.push(dir.clone());
        }

        if let Some(exe_dir) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
        {
            #[cfg(target_os = "macos")]
            if exe_dir
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "MacOS")
            {
                if let Some(contents_dir) = exe_dir.parent() {
                    roots.push(contents_dir.join("Resources"));
                }
            }

            roots.push(exe_dir);
        }

        roots
    }

    /// 在资源目录中查找文件（bundle.resources 保留 `resources/` 相对路径）
    fn find_resource(&self, file_name: &str) -> Option<PathBuf> {
        self.candidate_resource_roots()
            .into_iter()
            .map(|root| root.join("resources").join(file_name))
            .find(|path| path.is_file())
    }

    /// 获取 privacy-filter 二进制文件路径
    fn get_binary_path(&self) -> Result<PathBuf, AppError> {
        let (os, arch) = Self::go_platform_suffix();
        let exe_name = if cfg!(target_os = "windows") {
            format!("privacy-filter-{}-{}.exe", os, arch)
        } else {
            format!("privacy-filter-{}-{}", os, arch)
        };

        self.find_resource(&exe_name).ok_or_else(|| {
            AppError::Config(format!(
                "Privacy filter binary not found: {} (searched resources/ under resource dir and executable dir)",
                exe_name
            ))
        })
    }

    /// 启动服务子进程（不等待就绪，就绪等待见 `wait_until_healthy`）
    pub fn start(&self) -> Result<(), AppError> {
        let mut process_guard = self
            .process
            .lock()
            .map_err(|e| AppError::Config(format!("Failed to lock process mutex: {}", e)))?;

        // 如果已经在运行，先停止
        if let Some(mut child) = process_guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }

        let binary_path = self.get_binary_path()?;

        // 清理上次异常退出残留的孤儿进程：它们仍占用端口，会让本次 spawn 的
        // 新进程绑定失败而立即退出，但健康检查又命中旧孤儿进程造成"假健康"。
        cleanup_orphaned_on_port(self.port);

        log::info!(
            "[PrivacyFilter] Starting service on port {} with binary: {}",
            self.port,
            binary_path.display()
        );

        let mut command = Command::new(&binary_path);
        command
            .env("PF_PORT", self.port.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        // 指定打包的 gitleaks 规则集；缺失时 privacy-filter 回退到内置兜底规则
        if let Some(rules_path) = self.find_resource("gitleaks.toml") {
            command.env("PF_GITLEAKS_TOML", &rules_path);
            log::info!(
                "[PrivacyFilter] Using gitleaks rules: {}",
                rules_path.display()
            );
        } else {
            log::warn!(
                "[PrivacyFilter] gitleaks.toml not found in resources, falling back to built-in rules"
            );
        }

        let child = command
            .spawn()
            .map_err(|e| AppError::Config(format!("Failed to start privacy-filter: {}", e)))?;

        *process_guard = Some(child);
        Ok(())
    }

    /// 等待服务就绪（启动后轮询健康检查）
    ///
    /// 先确认自己 spawn 的子进程仍然存活，再做 HTTP 健康检查：若子进程已退出
    /// （端口被第三方程序占用、二进制缺失等），直接失败而非被残留旧进程的响应误导。
    pub async fn wait_until_healthy(&self) -> Result<(), AppError> {
        for _ in 0..STARTUP_PROBE_ATTEMPTS {
            if !self.is_running() {
                return Err(AppError::Config(format!(
                    "Privacy filter exited during startup (port {} may be in use)",
                    self.port
                )));
            }
            if self.health_check().await {
                log::info!("[PrivacyFilter] Service is healthy on port {}", self.port);
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(STARTUP_PROBE_INTERVAL_MS)).await;
        }

        Err(AppError::Config(format!(
            "Privacy filter did not become healthy on port {} in time",
            self.port
        )))
    }

    /// 停止服务
    pub fn stop(&self) -> Result<(), AppError> {
        let mut process_guard = self
            .process
            .lock()
            .map_err(|e| AppError::Config(format!("Failed to lock process mutex: {}", e)))?;

        if let Some(mut child) = process_guard.take() {
            log::info!("[PrivacyFilter] Stopping service");
            let _ = child.kill();
            let _ = child.wait();
            log::info!("[PrivacyFilter] Service stopped");
        }

        Ok(())
    }

    /// 检查子进程是否存活（`try_wait` 探测，进程崩溃后返回 false）
    pub fn is_running(&self) -> bool {
        let Ok(mut guard) = self.process.lock() else {
            return false;
        };

        match guard.as_mut() {
            Some(child) => match child.try_wait() {
                // 已退出：清理句柄
                Ok(Some(_)) => {
                    *guard = None;
                    false
                }
                Ok(None) => true,
                Err(_) => false,
            },
            None => false,
        }
    }

    /// 健康检查（上游返回 `{"status":"ok",...}`）
    pub async fn health_check(&self) -> bool {
        let url = format!("http://127.0.0.1:{}/health", self.port);

        match shared_client().get(&url).send().await {
            Ok(response) if response.status().is_success() => response
                .json::<HealthResponse>()
                .await
                .map(|health| health.status == "ok")
                .unwrap_or(false),
            _ => false,
        }
    }

    /// 过滤单个文本（设置页"测试过滤"使用）
    pub async fn redact(&self, text: String) -> Result<RedactResponse, AppError> {
        let url = format!("http://127.0.0.1:{}/redact", self.port);
        let request = RedactRequest { text };

        let response = shared_client()
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| AppError::Config(format!("Privacy filter request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(AppError::Config(format!(
                "Privacy filter returned status: {}",
                response.status()
            )));
        }

        response
            .json::<RedactResponse>()
            .await
            .map_err(|e| AppError::Config(format!("Failed to parse response: {}", e)))
    }

    /// 获取服务状态
    pub async fn get_status(&self) -> PrivacyFilterStatus {
        let running = self.is_running();
        let healthy = if running {
            self.health_check().await
        } else {
            false
        };

        PrivacyFilterStatus {
            running,
            port: self.port,
            healthy,
            error: None,
        }
    }
}

impl Drop for PrivacyFilterService {
    fn drop(&mut self) {
        // 兜底清理；正常退出路径由 cleanup_before_exit 显式停止
        let _ = self.stop();
    }
}

// ============================================================
// 请求体文本字段的提取与回填
// ============================================================

/// JSON 路径（对象键或数组下标的字符串形式）与对应文本
type TextEntry = (Vec<String>, String);

/// 从请求体中提取需要过滤的文本字段。
///
/// 覆盖代理支持的各 API 格式：
/// - Claude Messages API：`system`（string/array）、`messages[].content`
///   （string/array，含 `tool_result` 嵌套 content）
/// - OpenAI Chat Completions：`messages[].content`（string/array，与 Claude 同构）
/// - OpenAI Responses API（Codex CLI 主路径）：`instructions`、`input`
///   （string/array，含 message item 的 content 与 `function_call_output` 的 output）
/// - Gemini：`systemInstruction`/`system_instruction` 与 `contents[].parts[].text`
pub fn extract_texts_from_body(body: &serde_json::Value) -> Vec<TextEntry> {
    let mut texts = Vec::new();

    // Claude: system 为 string 或 [{type:"text", text}]
    if let Some(system) = body.get("system") {
        collect_content_value(&mut texts, vec!["system".to_string()], system);
    }

    // Claude / OpenAI Chat Completions: messages[].content
    if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
        for (i, msg) in messages.iter().enumerate() {
            if let Some(content) = msg.get("content") {
                collect_content_value(
                    &mut texts,
                    vec!["messages".to_string(), i.to_string(), "content".to_string()],
                    content,
                );
            }
        }
    }

    // 旧式 Completions: prompt 为 string
    if let Some(prompt) = body.get("prompt").and_then(|p| p.as_str()) {
        texts.push((vec!["prompt".to_string()], prompt.to_string()));
    }

    // OpenAI Responses API: instructions 为 string
    if let Some(instructions) = body.get("instructions").and_then(|s| s.as_str()) {
        texts.push((vec!["instructions".to_string()], instructions.to_string()));
    }

    // OpenAI Responses API: input 为 string 或 item 数组
    if let Some(input) = body.get("input") {
        if let Some(text) = input.as_str() {
            texts.push((vec!["input".to_string()], text.to_string()));
        } else if let Some(items) = input.as_array() {
            for (i, item) in items.iter().enumerate() {
                let item_path = vec!["input".to_string(), i.to_string()];

                // message item: content 为 string 或 [{type:"input_text"/"output_text", text}]
                if let Some(content) = item.get("content") {
                    let mut path = item_path.clone();
                    path.push("content".to_string());
                    collect_content_value(&mut texts, path, content);
                }

                // function_call_output item: output 为 string（工具输出常含敏感内容）
                if let Some(output) = item.get("output").and_then(|o| o.as_str()) {
                    let mut path = item_path;
                    path.push("output".to_string());
                    texts.push((path, output.to_string()));
                }
            }
        }
    }

    // Gemini: systemInstruction（v1beta REST 也接受 snake_case）
    for key in ["systemInstruction", "system_instruction"] {
        if let Some(instruction) = body.get(key) {
            collect_gemini_parts(&mut texts, vec![key.to_string()], instruction);
        }
    }

    // Gemini: contents[].parts[].text
    if let Some(contents) = body.get("contents").and_then(|c| c.as_array()) {
        for (i, content) in contents.iter().enumerate() {
            collect_gemini_parts(
                &mut texts,
                vec!["contents".to_string(), i.to_string()],
                content,
            );
        }
    }

    texts
}

/// 收集 Claude/OpenAI 风格的 content 值：
/// string 直接收集；array 则收集每项的 `text` 字段，
/// 并递归 `tool_result` 块的嵌套 `content`。
fn collect_content_value(
    texts: &mut Vec<TextEntry>,
    path: Vec<String>,
    content: &serde_json::Value,
) {
    if let Some(text) = content.as_str() {
        texts.push((path, text.to_string()));
        return;
    }

    if let Some(blocks) = content.as_array() {
        for (i, block) in blocks.iter().enumerate() {
            if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                let mut block_path = path.clone();
                block_path.push(i.to_string());
                block_path.push("text".to_string());
                texts.push((block_path, text.to_string()));
            }

            // Claude tool_result: {type:"tool_result", content: string | [{type:"text", text}]}
            if let Some(nested) = block.get("content") {
                let mut nested_path = path.clone();
                nested_path.push(i.to_string());
                nested_path.push("content".to_string());
                collect_content_value(texts, nested_path, nested);
            }
        }
    }
}

/// 收集 Gemini content 对象的 parts[].text
fn collect_gemini_parts(
    texts: &mut Vec<TextEntry>,
    path: Vec<String>,
    content: &serde_json::Value,
) {
    if let Some(parts) = content.get("parts").and_then(|p| p.as_array()) {
        for (i, part) in parts.iter().enumerate() {
            if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                let mut part_path = path.clone();
                part_path.push("parts".to_string());
                part_path.push(i.to_string());
                part_path.push("text".to_string());
                texts.push((part_path, text.to_string()));
            }
        }
    }
}

/// 将过滤后的文本按路径替换回请求体
pub fn replace_texts_in_body(body: &mut serde_json::Value, replacements: &[TextEntry]) {
    for (path, new_text) in replacements {
        if path.is_empty() {
            continue;
        }
        navigate_and_replace(body, path, new_text);
    }
}

/// 按路径递归导航并替换叶子节点为字符串
fn navigate_and_replace(current: &mut serde_json::Value, path: &[String], new_text: &str) {
    use serde_json::Value;

    let key = &path[0];
    let remaining = &path[1..];

    if remaining.is_empty() {
        match current {
            Value::Object(obj) => {
                obj.insert(key.clone(), Value::String(new_text.to_string()));
            }
            Value::Array(arr) => {
                if let Ok(index) = key.parse::<usize>() {
                    if index < arr.len() {
                        arr[index] = Value::String(new_text.to_string());
                    }
                }
            }
            _ => {}
        }
        return;
    }

    match current {
        Value::Array(arr) => {
            if let Ok(index) = key.parse::<usize>() {
                if let Some(next) = arr.get_mut(index) {
                    navigate_and_replace(next, remaining, new_text);
                }
            }
        }
        Value::Object(obj) => {
            if let Some(next) = obj.get_mut(key) {
                navigate_and_replace(next, remaining, new_text);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_claude_messages_and_system() {
        let body = json!({
            "system": "system prompt",
            "messages": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": [{"type": "text", "text": "world"}]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": [
                        {"type": "text", "text": "tool output"}
                    ]}
                ]}
            ]
        });

        let texts = extract_texts_from_body(&body);
        let values: Vec<&str> = texts.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(
            values,
            vec!["system prompt", "hello", "world", "tool output"]
        );
    }

    #[test]
    fn extracts_responses_api_input() {
        let body = json!({
            "instructions": "be helpful",
            "input": [
                {"type": "message", "role": "user", "content": [
                    {"type": "input_text", "text": "my email is a@b.com"}
                ]},
                {"type": "function_call_output", "call_id": "c1", "output": "secret data"}
            ]
        });

        let texts = extract_texts_from_body(&body);
        let values: Vec<&str> = texts.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(
            values,
            vec!["be helpful", "my email is a@b.com", "secret data"]
        );
    }

    #[test]
    fn extracts_gemini_contents_and_system_instruction() {
        let body = json!({
            "systemInstruction": {"parts": [{"text": "sys"}]},
            "contents": [
                {"role": "user", "parts": [{"text": "hi"}, {"inlineData": {}}]}
            ]
        });

        let texts = extract_texts_from_body(&body);
        let values: Vec<&str> = texts.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(values, vec!["sys", "hi"]);
    }

    #[test]
    fn replaces_texts_at_extracted_paths() {
        let mut body = json!({
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "original"}]}
            ]
        });

        let texts = extract_texts_from_body(&body);
        let replacements: Vec<TextEntry> = texts
            .into_iter()
            .map(|(path, _)| (path, "[REDACTED]".to_string()))
            .collect();
        replace_texts_in_body(&mut body, &replacements);

        assert_eq!(
            body["messages"][0]["content"][0]["text"],
            json!("[REDACTED]")
        );
    }

    #[test]
    fn replace_string_input_at_top_level() {
        let mut body = json!({"input": "raw text", "model": "gpt-x"});
        let texts = extract_texts_from_body(&body);
        assert_eq!(texts.len(), 1);

        let replacements = vec![(texts[0].0.clone(), "[FILTERED]".to_string())];
        replace_texts_in_body(&mut body, &replacements);
        assert_eq!(body["input"], json!("[FILTERED]"));
        assert_eq!(body["model"], json!("gpt-x"));
    }
}
