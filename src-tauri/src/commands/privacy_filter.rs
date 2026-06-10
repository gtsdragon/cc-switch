//! Privacy Filter 命令接口
//!
//! 提供 Tauri 命令用于管理隐私过滤服务。

use crate::privacy_filter::{PrivacyFilterService, PrivacyFilterStatus, DEFAULT_PORT};
use crate::store::AppState;
use std::path::PathBuf;
use tauri::{Manager, State};

/// 全局隐私过滤服务状态
#[derive(Default)]
pub struct PrivacyFilterState {
    pub service: tokio::sync::Mutex<Option<PrivacyFilterService>>,
}

impl PrivacyFilterState {
    pub fn new() -> Self {
        Self::default()
    }
}

/// 获取 Tauri 资源目录（用于定位打包的二进制与规则文件）
fn resource_dir(app: &tauri::AppHandle) -> Option<PathBuf> {
    app.path().resource_dir().ok()
}

/// 启动隐私过滤服务
#[tauri::command]
pub async fn start_privacy_filter_service(
    app: tauri::AppHandle,
    state: State<'_, PrivacyFilterState>,
    app_state: State<'_, AppState>,
) -> Result<(), String> {
    start_service_internal(&state, app_state.db.as_ref(), resource_dir(&app)).await
}

/// 内部启动函数（命令、配置切换与应用启动自启动共用）。
///
/// 启动子进程后等待健康检查通过，失败（如端口被占用、二进制缺失）时
/// 回收进程并返回错误，避免 UI 显示"运行中"而实际不可用。
pub async fn start_service_internal(
    state: &PrivacyFilterState,
    db: &crate::database::Database,
    resource_dir: Option<PathBuf>,
) -> Result<(), String> {
    let port = db
        .get_setting("privacy_filter_port")
        .map_err(|e| e.to_string())?
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);

    let mut service_guard = state.service.lock().await;

    // 停止旧实例（如果有），避免遗留子进程
    if let Some(old) = service_guard.take() {
        let _ = old.stop();
    }

    let service = PrivacyFilterService::new(port, resource_dir);
    service.start().map_err(|e| e.to_string())?;

    if let Err(e) = service.wait_until_healthy().await {
        let _ = service.stop();
        return Err(e.to_string());
    }

    *service_guard = Some(service);

    log::info!("[Command] Privacy filter service started on port {}", port);
    Ok(())
}

/// 停止隐私过滤服务
#[tauri::command]
pub async fn stop_privacy_filter_service(
    state: State<'_, PrivacyFilterState>,
) -> Result<(), String> {
    stop_service_internal(&state).await
}

/// 内部停止函数，用于配置切换与退出清理
pub async fn stop_service_internal(state: &PrivacyFilterState) -> Result<(), String> {
    let mut service_guard = state.service.lock().await;

    if let Some(service) = service_guard.take() {
        service.stop().map_err(|e| e.to_string())?;
        log::info!("[Command] Privacy filter service stopped");
    }

    Ok(())
}

/// 获取隐私过滤服务状态
#[tauri::command]
pub async fn get_privacy_filter_status(
    state: State<'_, PrivacyFilterState>,
    app_state: State<'_, AppState>,
) -> Result<PrivacyFilterStatus, String> {
    let service_guard = state.service.lock().await;

    if let Some(service) = service_guard.as_ref() {
        Ok(service.get_status().await)
    } else {
        let port = app_state
            .db
            .get_setting("privacy_filter_port")
            .ok()
            .flatten()
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(DEFAULT_PORT);

        Ok(PrivacyFilterStatus {
            running: false,
            port,
            healthy: false,
            error: None,
        })
    }
}

/// 测试隐私过滤功能
#[tauri::command]
pub async fn test_privacy_filter(
    state: State<'_, PrivacyFilterState>,
    test_text: String,
) -> Result<String, String> {
    let service_guard = state.service.lock().await;

    if let Some(service) = service_guard.as_ref() {
        let response = service.redact(test_text).await.map_err(|e| e.to_string())?;

        Ok(response.redacted)
    } else {
        Err("Privacy filter service is not running".to_string())
    }
}

/// 获取隐私过滤配置
#[tauri::command]
pub async fn get_privacy_filter_config(
    app_state: State<'_, AppState>,
) -> Result<PrivacyFilterConfig, String> {
    let db = app_state.db.as_ref();

    let enabled = db
        .get_bool_flag("privacy_filter_enabled")
        .map_err(|e| e.to_string())?;

    let port = db
        .get_setting("privacy_filter_port")
        .map_err(|e| e.to_string())?
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);

    Ok(PrivacyFilterConfig { enabled, port })
}

/// 设置隐私过滤配置
#[tauri::command]
pub async fn set_privacy_filter_config(
    app: tauri::AppHandle,
    app_state: State<'_, AppState>,
    state: State<'_, PrivacyFilterState>,
    config: PrivacyFilterConfig,
) -> Result<(), String> {
    if config.port < 1024 {
        return Err("Port must be between 1024 and 65535".to_string());
    }

    let db = app_state.db.as_ref();

    // 保存配置到数据库
    db.set_setting(
        "privacy_filter_enabled",
        if config.enabled { "true" } else { "false" },
    )
    .map_err(|e| e.to_string())?;

    db.set_setting("privacy_filter_port", &config.port.to_string())
        .map_err(|e| e.to_string())?;

    // 启用则（重）启动服务，禁用则停止
    if config.enabled {
        start_service_internal(&state, db, resource_dir(&app)).await?;
    } else {
        stop_service_internal(&state).await?;
    }

    log::info!(
        "[Command] Privacy filter config updated: enabled={}, port={}",
        config.enabled,
        config.port
    );

    Ok(())
}

/// 隐私过滤配置
#[derive(serde::Serialize, serde::Deserialize)]
pub struct PrivacyFilterConfig {
    pub enabled: bool,
    pub port: u16,
}
