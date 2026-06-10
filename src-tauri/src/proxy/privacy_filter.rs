//! 隐私过滤集成模块
//!
//! 在请求转发前调用 privacy-filter 服务过滤敏感信息。
//!
//! 过滤是尽力而为（best-effort）：服务不可用或解析失败时记录警告并
//! 返回原始请求体，不阻断请求。

use super::server::ProxyState;
use crate::privacy_filter::{extract_texts_from_body, redact_batch, replace_texts_in_body, DEFAULT_PORT};
use serde_json::Value;

/// 过滤请求体中的敏感信息。
///
/// 提取文本字段 → 调用 privacy-filter 批量接口 → 将命中的结果替换回请求体。
/// 任一环节失败均降级返回原始请求体。
pub async fn filter_sensitive_data(state: &ProxyState, body: Value, tag: &str) -> Value {
    // 提取需要过滤的文本字段
    let texts_to_filter = extract_texts_from_body(&body);

    if texts_to_filter.is_empty() {
        log::debug!("[{}] Privacy filter: no text fields to filter", tag);
        return body;
    }

    let port = state
        .db
        .get_setting("privacy_filter_port")
        .ok()
        .flatten()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(DEFAULT_PORT);

    let texts: Vec<String> = texts_to_filter
        .iter()
        .map(|(_, text)| text.clone())
        .collect();

    let results = match redact_batch(port, &texts).await {
        Ok(results) => results,
        Err(e) => {
            log::warn!(
                "[{}] Privacy filter unavailable, forwarding original body: {}",
                tag,
                e
            );
            return body;
        }
    };

    if results.len() != texts_to_filter.len() {
        log::warn!(
            "[{}] Privacy filter returned {} results for {} texts, forwarding original body",
            tag,
            results.len(),
            texts_to_filter.len()
        );
        return body;
    }

    // 统计并仅替换有命中的字段
    let total_hits: usize = results.iter().map(|r| r.count).sum();
    if total_hits == 0 {
        log::debug!("[{}] Privacy filter: no sensitive content detected", tag);
        return body;
    }

    log::info!(
        "[{}] Privacy filter: {} sensitive item(s) redacted",
        tag,
        total_hits
    );

    let replacements: Vec<(Vec<String>, String)> = texts_to_filter
        .into_iter()
        .zip(results.iter())
        .filter(|(_, result)| result.hit)
        .map(|((path, _), result)| (path, result.redacted.clone()))
        .collect();

    let mut body = body;
    replace_texts_in_body(&mut body, &replacements);
    body
}
