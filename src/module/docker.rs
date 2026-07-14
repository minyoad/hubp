use crate::core::{Config, ProxyProvider};
use ax_http::HeaderMap;

/// Docker 镜像代理服务实现
pub struct DockerProvider;

use axum::http as ax_http;

impl DockerProvider {
    pub fn new() -> Self {
        Self
    }

    fn get_query_param<'a>(&self, query: &'a str, key: &str) -> Option<&'a str> {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == key {
                    return Some(v);
                }
            }
        }
        None
    }
}

impl ProxyProvider for DockerProvider {
    fn matches(&self, path: &str) -> bool {
        path.starts_with("v2/") || path.starts_with("token")
    }

    fn upstream_host(&self, path: &str, config: &Config) -> Option<String> {
        if path.starts_with("v2/") {
            let inner_path = &path[3..];
            for (domain, mapping) in &config.docker.registries {
                if !mapping.enabled { continue; }
                if inner_path == *domain || (inner_path.starts_with(domain) && inner_path[domain.len()..].starts_with('/')) {
                    return Some(mapping.upstream.clone());
                }
            }
            return config.docker.registries.get("docker.io").map(|m| m.upstream.clone());
        }
        if path.starts_with("token") {
            let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            if let Some(service) = self.get_query_param(query, "service") {
                for mapping in config.docker.registries.values() {
                    if mapping.enabled && (service == mapping.upstream || service.starts_with(&mapping.upstream)) {
                        return mapping.auth_host.split('/').next().map(|s| s.to_string());
                    }
                }
            }
        }
        None
    }

    fn transform(&self, path: String, config: &Config) -> String {
        if path.starts_with("v2/") {
            let inner_path = &path[3..];
            for (domain, mapping) in &config.docker.registries {
                if !mapping.enabled { continue; }
                if inner_path == *domain || (inner_path.starts_with(domain) && inner_path[domain.len()..].starts_with('/')) {
                    let remaining = if inner_path.len() <= domain.len() { "" } else { &inner_path[domain.len() + 1..] };
                    return format!("https://{}/v2/{}", mapping.upstream, remaining);
                }
            }
            let upstream = config.docker.registries.get("docker.io").map(|m| m.upstream.as_str()).unwrap_or("registry-1.docker.io");
            return format!("https://{}/v2/{}", upstream, inner_path);
        } else if path.starts_with("token") {
            let query = path.split_once('?').map(|(_, q)| q).unwrap_or("");
            let mut target_auth_host = "auth.docker.io/token".to_string();
            let mut matched_domain: Option<String> = None;
            if let Some(service) = self.get_query_param(query, "service") {
                for (domain, mapping) in &config.docker.registries {
                    if mapping.enabled && (service == mapping.upstream || service.starts_with(&mapping.upstream)) {
                        target_auth_host = mapping.auth_host.clone();
                        matched_domain = Some(domain.clone());
                        break;
                    }
                }
            }
            // Docker 客户端会把镜像的完整路径作为 scope，包含 registry 域名前缀
            // 例如 scope=repository:gcr.io/google-containers/pause:pull
            // 但上游 token 端点期望的是去掉前缀的 scope=repository:google-containers/pause:pull
            // 这里匹配后剥离对应 registry 的域名前缀
            if query.is_empty() {
                format!("https://{}", target_auth_host)
            } else if let Some(ref domain) = matched_domain {
                let fixed_query = DockerProvider::strip_scope_prefix(query, domain);
                format!("https://{}?{}", target_auth_host, fixed_query)
            } else {
                format!("https://{}?{}", target_auth_host, query)
            }
        } else {
            path
        }
    }

    fn extract_keywords(&self, path: &str) -> Option<Vec<String>> {
        if path.starts_with("v2/") {
            let clean_path = path[3..].trim_start_matches('/');
            let parts: Vec<&str> = clean_path.split('/').collect();
            if parts.len() >= 2 {
                return Some(vec![parts[0].to_string(), parts[1].to_string()]);
            }
        }
        None
    }

    fn handle_response(&self, headers: &mut HeaderMap, config: &Config) {
        if let Some(auth_header) = headers.get_mut("www-authenticate") {
            if let Ok(auth_str) = auth_header.to_str() {
                let mut new_auth = auth_str.to_string();
                for mapping in config.docker.registries.values() {
                    if !mapping.enabled { continue; }
                    let full_auth_url = format!("https://{}", mapping.auth_host);
                    if !new_auth.contains(&full_auth_url) { continue; }

                    // 仅当满足以下任一条件时才重写 realm，让 Docker 客户端通过代理获取 token：
                    // 1. auth 端点与 registry 不在同一域名 (如 docker.io auth → registry-1)
                    // 2. 配置了认证凭据需要注入 (如 ghcr.io 的 PAT)
                    let auth_host_domain = mapping.auth_host.split('/').next().unwrap_or("");
                    let should_rewrite = auth_host_domain != mapping.upstream || !mapping.username.is_empty();
                    if should_rewrite {
                        new_auth = new_auth.replace(&full_auth_url, "/token");
                    }
                }
                if !new_auth.contains("/token") && new_auth.contains("auth.docker.io/token") {
                    new_auth = new_auth.replace("https://auth.docker.io/token", "/token");
                }
                if let Ok(new_val) = ax_http::HeaderValue::from_str(&new_auth) {
                    *auth_header = new_val;
                }
            }
        }
    }
}

impl DockerProvider {
    /// 剥离 scope=repository: 中的 registry 域名前缀
    fn strip_scope_prefix(query: &str, domain: &str) -> String {
        let prefix = format!("repository:{}", domain);
        query.split('&')
            .map(|param| {
                if let Some((k, v)) = param.split_once('=') {
                    if k == "scope" && v.starts_with(&prefix) {
                        let rest = &v[prefix.len()..];
                        // 确保前缀后是 '/' (避免误匹配子域名)
                        if rest.starts_with('/') {
                            return format!("scope=repository:{}", &rest[1..]);
                        }
                        // 整段就是域名本身 (如 scope=repository:docker.io:pull)
                        if rest.starts_with(':') {
                            return format!("scope=repository:{}", &rest[1..]);
                        }
                    }
                }
                param.to_string()
            })
            .collect::<Vec<_>>()
            .join("&")
    }
}
