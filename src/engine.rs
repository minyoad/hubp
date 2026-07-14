use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use crate::core::{AppState, ProxyProvider};
use crate::utils::normalize_url;

/// 核心代理转发引擎
pub async fn do_proxy(
    state: Arc<AppState>, 
    req: Request, 
    target_url: String, 
    depth: u8,
    provider: Option<Arc<dyn ProxyProvider>>
) -> Response {
    if depth >= 10 {
        return (StatusCode::LOOP_DETECTED, "Too many redirects.").into_response();
    }
    
    // 规范化目标 URL
    let target_url = normalize_url(&target_url);

    let path = req.uri().path().to_string(); 
    let method = req.method().clone();
    let req_headers = req.headers().clone();
    let body = req.into_body();

    // 1. 构造转发请求
    let proxy_req_builder = {
        let client = state.http_client.read().await;
        client.request(method, &target_url)
    };
    
    let mut proxy_req_builder = proxy_req_builder;
    
    // 2. 处理请求头
    for (key, value) in &req_headers {
        if key == axum::http::header::HOST {
            continue;
        }
        
        if key == axum::http::header::REFERER {
            if let (Some(ref p), Ok(_val_str)) = (&provider, value.to_str()) {
                let config = state.config.read().await;
                if let Some(upstream_host) = p.upstream_host(&path, &config) {
                    let new_referer = format!("https://{}/", upstream_host);
                    if let Ok(v) = HeaderValue::from_str(&new_referer) {
                        proxy_req_builder = proxy_req_builder.header(key, v);
                        continue;
                    }
                }
            }
        }
        
        proxy_req_builder = proxy_req_builder.header(key, value.clone());
    }

    // 对 Docker Hub 的请求添加 registry 认证 (解决 PAT 强制要求)
    // 仅当客户端自身未携带 Authorization 头时才注入，避免覆盖客户端的私有仓库凭证
    if !req_headers.contains_key(axum::http::header::AUTHORIZATION) {
        if let Some(host) = extract_host(&target_url) {
            let config = state.config.read().await;
            for mapping in config.docker.registries.values() {
                if !mapping.enabled || mapping.username.is_empty() {
                    continue;
                }
                let auth_host_name = mapping.auth_host.split('/').next().unwrap_or("");
                if host == mapping.upstream || host == auth_host_name {
                    proxy_req_builder = proxy_req_builder.basic_auth(&mapping.username, Some(&mapping.password));
                    break;
                }
            }
        }
    }

    // 3. 发起请求
    let proxy_req = match proxy_req_builder.body(reqwest::Body::wrap_stream(body.into_data_stream())).send().await {
        Ok(res) => res,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("server error {}", e)).into_response(),
    };

    let status = proxy_req.status();
    let headers = proxy_req.headers().clone();

    // 4. 文件大小检查
    if let Some(content_length) = headers.get(axum::http::header::CONTENT_LENGTH) {
        if let Ok(size) = content_length.to_str().unwrap_or("0").parse::<i64>() {
            let config = state.config.read().await;
            let limit_size = config.request_limit.limit_size;
            if limit_size > 0 {
                let limit_bytes = limit_size * 1024 * 1024;
                if size > limit_bytes {
                    return (StatusCode::PAYLOAD_TOO_LARGE, "File too large.").into_response();
                }
            }
        }
    }

    // 5. 清洗并重写响应头
    let mut res_headers = HeaderMap::new();
    for (key, value) in headers {
        if let Some(k) = key {
            let k_str = k.as_str().to_lowercase();
            if k_str != "content-security-policy" && k_str != "referrer-policy" && k_str != "strict-transport-security" {
                res_headers.insert(k, value);
            }
        }
    }

    if let Some(ref p) = provider {
        let config = state.config.read().await;
        p.handle_response(&mut res_headers, &config);
    }

    // 修复 Docker WWW-Authenticate 中的相对路径 realm：
    // handle_response 会将 realm 的绝对 URL 改写为相对路径，
    // 但 Docker 客户端（Go 实现）无法正确解析相对 realm URL，
    // 导致 "unsupported protocol scheme" 或以错误 host 请求 token。
    // 这里利用原始请求的 Host 头将相对 realm 补全为绝对 URL。
    // 使用正则精准替换 realm 属性值，避免误改 service 等其他字段。
    if let Some(auth_header) = res_headers.get_mut(axum::http::header::WWW_AUTHENTICATE) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(host) = req_headers.get(axum::http::header::HOST) {
                if let Ok(host_str) = host.to_str() {
                    let re = regex::Regex::new(r#"realm="/([^"]*)""#).unwrap();
                    if re.is_match(auth_str) {
                        let new_auth = re.replace(auth_str, format!(r#"realm="https://{}/$1""#, host_str));
                        if let Ok(new_val) = HeaderValue::from_str(&new_auth) {
                            *auth_header = new_val;
                        }
                    }
                }
            }
        }
    }

    // 6. 处理重定向
    if let Some(location) = res_headers.get(axum::http::header::LOCATION) {
        if let Ok(loc_str) = location.to_str() {
            let loc_str = loc_str.to_string();
            
            // 判定当前上下文类型
            let current_kind = provider.as_ref().map(|p| p.kind()).unwrap_or(crate::core::ProviderKind::Explicit);

            match current_kind {
                crate::core::ProviderKind::Explicit => {
                    // 如果是显式代理请求触发的重定向
                    // 1. 尝试看是否有更精确的 Explicit Provider 认领
                    let next_provider = state.find_provider(&loc_str, crate::core::ProviderKind::Explicit);
                    
                    // 2. 如果重定向目标也是绝对 URL (以 http 开头)，则直接服务器内部递归跳转
                    //    这样即使跳转到 codeload 等未知域名，由于没有 Provider 认领，也会进入内部跳转逻辑。
                    if loc_str.starts_with("http") {
                        return Box::pin(do_proxy(state.clone(), Request::new(Body::empty()), loc_str, depth + 1, next_provider)).await;
                    }
                }
                crate::core::ProviderKind::Web => {
                    // 如果是 Web 浏览请求触发的重定向
                    // 1. 优先检查是否重定向到了一个“显式资源”（如 raw 文件、下载链接）
                    if let Some(_) = state.find_provider(&loc_str, crate::core::ProviderKind::Explicit) {
                        let new_loc = format!("/{}", loc_str);
                        res_headers.insert(axum::http::header::LOCATION, HeaderValue::from_str(&new_loc).unwrap());
                    } else {
                        // 2. 否则，看是否有 Web Provider 认领
                        let next_provider = state.find_provider(&loc_str, crate::core::ProviderKind::Web);
                        if next_provider.is_some() {
                            let new_loc = format!("/{}", loc_str);
                            res_headers.insert(axum::http::header::LOCATION, HeaderValue::from_str(&new_loc).unwrap());
                        } else {
                            // 3. 既不是显式资源也不是可处理的 Web 页面，执行内部静默跟随
                            return Box::pin(do_proxy(state.clone(), Request::new(Body::empty()), loc_str, depth + 1, next_provider)).await;
                        }
                    }
                }
            }
        }
    }

    // 7. 处理体改写
    let is_html = res_headers.get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("text/html"))
        .unwrap_or(false);

    if is_html {
        if let Some(ref p) = provider {
            let config = state.config.read().await;
            let body_bytes = match proxy_req.bytes().await {
                Ok(b) => b,
                Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, format!("read error {}", e)).into_response(),
            };
            
            if let Ok(body_str) = String::from_utf8(body_bytes.to_vec()) {
                if let Some(rewritten) = p.rewrite_body(&path, body_str, &config, &req_headers) {
                    let mut builder = Response::builder().status(status);
                    *builder.headers_mut().unwrap() = res_headers;
                    builder = builder.header(axum::http::header::CONTENT_LENGTH, rewritten.len());
                    return builder.body(Body::from(rewritten)).unwrap();
                }
            }
            
            let mut builder = Response::builder().status(status);
            *builder.headers_mut().unwrap() = res_headers;
            return builder.body(Body::from(body_bytes)).unwrap();
        }
    }

    let mut builder = Response::builder().status(status);
    *builder.headers_mut().unwrap() = res_headers;
    let body = Body::from_stream(proxy_req.bytes_stream());
    builder.body(body).unwrap()
}

/// 自定义日志中间件引擎
pub async fn custom_logger_engine(
    State(_state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    if path == "/" {
        return next.run(req).await;
    }

    let start = std::time::Instant::now();
    let method = req.method().clone();
    let user_agent = req.headers().get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("unknown").to_string();
    
    let response = next.run(req).await;
    
    let latency = start.elapsed();
    let status = response.status();

    if status == axum::http::StatusCode::OK {
        tracing::debug!(
            "{} | {:?} | {:?} | {} | {}",
            status.as_u16(),
            latency,
            method,
            path,
            user_agent
        );
    } else {
        tracing::info!(
            "{} | {:?} | {:?} | {} | {}",
            status.as_u16(),
            latency,
            method,
            path,
            user_agent
        );
    }

    response
}

/// 列表匹配辅助工具
pub fn check_list(keywords: &[String], list: &[String]) -> bool {
    if keywords.is_empty() || list.is_empty() {
        return false;
    }

    let target = keywords.join("/");

    for pattern in list {
        if pattern == "*" {
            return true;
        }
        
        if pattern.contains('*') {
            let regex_pattern = format!("^{}$", pattern.replace(".", "\\.").replace("*", ".*"));
            if let Ok(re) = regex::Regex::new(&regex_pattern) {
                if re.is_match(&target) {
                    return true;
                }
            }
        } else {
            if target.starts_with(pattern) || pattern == &target {
                return true;
            }
        }
    }
    false
}

/// 从 URL 中提取主机名（不含端口）
fn extract_host(url: &str) -> Option<&str> {
    let without_scheme = url.strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    without_scheme.split('/').next()
}
