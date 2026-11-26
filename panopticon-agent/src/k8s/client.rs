//! A small Kubernetes API client: in-cluster detection, paginated list and
//! watch, over HTTPS with the service-account CA and bearer token.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::de::DeserializeOwned;

use super::model::{ObjectList, WatchEvent};

/// Default service-account mount.
pub const SERVICE_ACCOUNT_DIR: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

/// Items per list page.
pub const PAGE_LIMIT: usize = 500;

/// Longest single watch-stream line accepted (one object).
const MAX_WATCH_LINE: usize = 16 * 1024 * 1024;

/// The in-cluster environment, as seen by a pod.
#[derive(Debug, Clone)]
pub struct ClusterEnv {
    pub service_host: Option<String>,
    pub service_port: Option<String>,
    pub service_account_dir: PathBuf,
}

impl ClusterEnv {
    pub fn from_process() -> Self {
        Self {
            service_host: std::env::var("KUBERNETES_SERVICE_HOST")
                .ok()
                .filter(|s| !s.is_empty()),
            service_port: std::env::var("KUBERNETES_SERVICE_PORT")
                .ok()
                .filter(|s| !s.is_empty()),
            service_account_dir: PathBuf::from(SERVICE_ACCOUNT_DIR),
        }
    }

    fn token_path(&self) -> PathBuf {
        self.service_account_dir.join("token")
    }

    fn ca_path(&self) -> PathBuf {
        self.service_account_dir.join("ca.crt")
    }

    /// Whether this looks like a pod with API access: the service env vars
    /// and a mounted token. (`enabled = "auto"` uses this.)
    pub fn is_in_cluster(&self) -> bool {
        self.service_host.is_some() && self.service_port.is_some() && self.token_path().is_file()
    }

    /// `https://host:port` (IPv6 hosts bracketed).
    pub fn api_base(&self) -> Option<String> {
        let host = self.service_host.as_deref()?;
        let port = self.service_port.as_deref()?;
        Some(if host.contains(':') && !host.starts_with('[') {
            format!("https://[{host}]:{port}")
        } else {
            format!("https://{host}:{port}")
        })
    }
}

/// Why an API request failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    /// Connection, TLS or timeout error.
    Transport(String),
    /// Non-success HTTP status.
    Status(u16, String),
    /// 410 Gone: the resourceVersion / continue token expired; re-list.
    Gone,
    /// Body was not the expected JSON.
    Decode(String),
}

impl ApiError {
    /// An operator-facing hint for the error, if there is an obvious one.
    pub fn hint(&self) -> Option<&'static str> {
        match self {
            ApiError::Status(401, _) => Some(
                "the service account token was rejected; check that the token is mounted \
                 (Helm: kubernetes.enabled=true) and not expired",
            ),
            ApiError::Status(403, _) => Some(
                "RBAC denies access; the agent's service account needs get/list/watch on \
                 pods and services cluster-wide (Helm: rbac.create=true)",
            ),
            ApiError::Transport(_) => Some("the API server is not reachable from this node"),
            _ => None,
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Transport(e) => write!(f, "transport error: {e}"),
            ApiError::Status(code, body) => write!(f, "HTTP {code}: {body}"),
            ApiError::Gone => write!(f, "HTTP 410 Gone (resource version expired)"),
            ApiError::Decode(e) => write!(f, "invalid response: {e}"),
        }
    }
}

fn transport(e: reqwest::Error) -> ApiError {
    // reqwest's Display omits the cause chain ("error sending request").
    let mut msg = e.to_string();
    let mut src = std::error::Error::source(&e);
    while let Some(s) = src {
        msg.push_str(": ");
        msg.push_str(&s.to_string());
        src = s.source();
    }
    ApiError::Transport(msg)
}

/// Where the bearer token comes from.
#[derive(Debug, Clone)]
enum Token {
    None,
    /// Re-read on every request: projected tokens are rotated by the kubelet.
    File(PathBuf),
    #[cfg(test)]
    Static(String),
}

/// A Kubernetes API client.
#[derive(Debug, Clone)]
pub struct ApiClient {
    base: String,
    token: Token,
    http: reqwest::Client,
}

impl ApiClient {
    /// The production client: `https://$KUBERNETES_SERVICE_HOST:$PORT`,
    /// trusting only the service-account CA, with the service-account token.
    pub fn in_cluster(env: &ClusterEnv) -> Result<Self, String> {
        let base = env
            .api_base()
            .ok_or("KUBERNETES_SERVICE_HOST / KUBERNETES_SERVICE_PORT not set")?;
        let token_path = env.token_path();
        if !token_path.is_file() {
            return Err(format!(
                "no service account token at {} (is automountServiceAccountToken off?)",
                token_path.display()
            ));
        }
        let ca_path = env.ca_path();
        let ca = std::fs::read(&ca_path)
            .map_err(|e| format!("cannot read {}: {e}", ca_path.display()))?;
        let certs = reqwest::Certificate::from_pem_bundle(&ca)
            .map_err(|e| format!("invalid CA bundle {}: {e}", ca_path.display()))?;
        if certs.is_empty() {
            return Err(format!("no certificates in {}", ca_path.display()));
        }
        let mut builder = base_builder().tls_built_in_root_certs(false);
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
        let http = builder
            .build()
            .map_err(|e| format!("cannot build HTTPS client: {e}"))?;
        Ok(Self {
            base,
            token: Token::File(token_path),
            http,
        })
    }

    /// A plain-HTTP client against `base` (fake API servers in tests).
    #[cfg(test)]
    pub fn plain_http(base: &str, token: Option<&str>) -> Self {
        Self {
            base: base.trim_end_matches('/').to_string(),
            token: token.map_or(Token::None, |t| Token::Static(t.to_string())),
            http: base_builder().build().unwrap(),
        }
    }

    pub fn base(&self) -> &str {
        &self.base
    }

    fn bearer(&self) -> Option<String> {
        match &self.token {
            Token::None => None,
            Token::File(p) => read_token(p),
            #[cfg(test)]
            Token::Static(t) => Some(t.clone()),
        }
    }

    async fn get(
        &self,
        path: &str,
        query: &[(&str, String)],
        timeout: Option<Duration>,
    ) -> Result<reqwest::Response, ApiError> {
        let mut req = self
            .http
            .get(format!("{}{}", self.base, path))
            .query(query)
            .header(reqwest::header::ACCEPT, "application/json");
        if let Some(t) = self.bearer() {
            req = req.bearer_auth(t);
        }
        if let Some(t) = timeout {
            req = req.timeout(t);
        }
        let resp = req.send().await.map_err(transport)?;
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        if status.as_u16() == 410 {
            return Err(ApiError::Gone);
        }
        let mut body = resp.text().await.unwrap_or_default();
        body.truncate(300);
        Err(ApiError::Status(status.as_u16(), body))
    }

    /// List every object at `path` (e.g. `/api/v1/pods`), following
    /// `continue` tokens. Returns the objects and the list's
    /// resourceVersion (where a watch should start).
    ///
    /// Pages are requested `limit=500` without a resourceVersion (a
    /// consistent read), which keeps each response, and the memory needed
    /// to parse it, bounded regardless of cluster size.
    pub async fn list_all<T: DeserializeOwned>(
        &self,
        path: &str,
        field_selector: Option<&str>,
    ) -> Result<(Vec<T>, String), ApiError> {
        let mut items = Vec::new();
        let mut cont: Option<String> = None;
        let mut pages = 0usize;
        loop {
            let mut query = vec![("limit", PAGE_LIMIT.to_string())];
            if let Some(fs) = field_selector {
                query.push(("fieldSelector", fs.to_string()));
            }
            if let Some(c) = &cont {
                query.push(("continue", c.clone()));
            }
            let resp = self
                .get(path, &query, Some(Duration::from_secs(60)))
                .await?;
            let bytes = resp.bytes().await.map_err(transport)?;
            let page: ObjectList<T> =
                serde_json::from_slice(&bytes).map_err(|e| ApiError::Decode(e.to_string()))?;
            items.extend(page.items);
            pages += 1;
            match page.metadata.continue_token.filter(|c| !c.is_empty()) {
                // A server that keeps returning tokens is broken; stop.
                Some(c) if pages < 10_000 => cont = Some(c),
                _ => {
                    let rv = page.metadata.resource_version.unwrap_or_default();
                    return Ok((items, rv));
                }
            }
        }
    }

    /// Watch `path` from `resource_version`, calling `on_event` for every
    /// event, until the server ends the stream (`timeout` elapses
    /// server-side) or an error occurs. Returns the last resourceVersion
    /// seen, from which the next watch can resume.
    pub async fn watch(
        &self,
        path: &str,
        field_selector: Option<&str>,
        resource_version: &str,
        timeout: Duration,
        mut on_event: impl FnMut(WatchEvent),
    ) -> Result<String, ApiError> {
        let secs = timeout.as_secs().max(1);
        let mut query = vec![
            ("watch", "1".to_string()),
            ("allowWatchBookmarks", "true".to_string()),
            ("timeoutSeconds", secs.to_string()),
            ("resourceVersion", resource_version.to_string()),
        ];
        if let Some(fs) = field_selector {
            query.push(("fieldSelector", fs.to_string()));
        }
        let mut rv = resource_version.to_string();
        // Client-side bound in case the server never closes the stream.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(secs + 30);
        let mut resp = tokio::time::timeout_at(deadline, self.get(path, &query, None))
            .await
            .map_err(|_| ApiError::Transport("watch request timed out".to_string()))??;
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let chunk = match tokio::time::timeout_at(deadline, resp.chunk()).await {
                Err(_) => return Ok(rv),
                Ok(r) => r.map_err(transport)?,
            };
            let Some(chunk) = chunk else {
                return Ok(rv);
            };
            buf.extend_from_slice(&chunk);
            while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buf.drain(..=pos).collect();
                let line = line.trim_ascii();
                if line.is_empty() {
                    continue;
                }
                let event: WatchEvent = serde_json::from_slice(line)
                    .map_err(|e| ApiError::Decode(format!("watch event: {e}")))?;
                if event.event_type == "ERROR" {
                    let code = event.object.get("code").and_then(|c| c.as_u64());
                    if code == Some(410) {
                        return Err(ApiError::Gone);
                    }
                    let msg = event
                        .object
                        .get("message")
                        .and_then(|m| m.as_str())
                        .unwrap_or("watch error")
                        .to_string();
                    return Err(ApiError::Status(code.unwrap_or(500) as u16, msg));
                }
                if let Some(v) = event
                    .object
                    .pointer("/metadata/resourceVersion")
                    .and_then(|v| v.as_str())
                {
                    rv = v.to_string();
                }
                on_event(event);
            }
            if buf.len() > MAX_WATCH_LINE {
                return Err(ApiError::Decode("watch event too large".to_string()));
            }
        }
    }
}

fn base_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        // The API server is reached directly; HTTPS_PROXY-style variables
        // meant for egress traffic must not capture it.
        .no_proxy()
        .connect_timeout(Duration::from_secs(5))
        .user_agent(concat!("panopticon-agent/", env!("CARGO_PKG_VERSION")))
}

fn read_token(path: &Path) -> Option<String> {
    let t = std::fs::read_to_string(path).ok()?;
    let t = t.trim();
    (!t.is_empty()).then(|| t.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_with(dir: &Path, host: Option<&str>, port: Option<&str>) -> ClusterEnv {
        ClusterEnv {
            service_host: host.map(String::from),
            service_port: port.map(String::from),
            service_account_dir: dir.to_path_buf(),
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "panopticon-k8s-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_in_cluster_detection() {
        let dir = temp_dir("detect");
        assert!(!env_with(&dir, Some("10.96.0.1"), Some("443")).is_in_cluster());
        std::fs::write(dir.join("token"), "abc").unwrap();
        assert!(env_with(&dir, Some("10.96.0.1"), Some("443")).is_in_cluster());
        assert!(!env_with(&dir, None, Some("443")).is_in_cluster());
        assert!(!env_with(&dir, Some("10.96.0.1"), None).is_in_cluster());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_api_base_ipv4_and_ipv6() {
        let dir = PathBuf::from("/nonexistent");
        assert_eq!(
            env_with(&dir, Some("10.96.0.1"), Some("443"))
                .api_base()
                .unwrap(),
            "https://10.96.0.1:443"
        );
        assert_eq!(
            env_with(&dir, Some("fd00:10:96::1"), Some("443"))
                .api_base()
                .unwrap(),
            "https://[fd00:10:96::1]:443"
        );
    }

    #[test]
    fn test_in_cluster_client_requires_token_and_valid_ca() {
        let dir = temp_dir("client");
        let env = env_with(&dir, Some("10.96.0.1"), Some("443"));
        let err = ApiClient::in_cluster(&env).unwrap_err();
        assert!(err.contains("token"), "{err}");

        std::fs::write(dir.join("token"), "abc\n").unwrap();
        let err = ApiClient::in_cluster(&env).unwrap_err();
        assert!(err.contains("ca.crt"), "{err}");

        std::fs::write(dir.join("ca.crt"), "not a certificate").unwrap();
        assert!(ApiClient::in_cluster(&env).is_err());

        std::fs::write(dir.join("ca.crt"), TEST_CA_PEM).unwrap();
        let client = ApiClient::in_cluster(&env).unwrap();
        assert_eq!(client.base(), "https://10.96.0.1:443");
        // Token is read from the file (trimmed) at request time.
        assert_eq!(client.bearer().as_deref(), Some("abc"));
        std::fs::write(dir.join("token"), "rotated").unwrap();
        assert_eq!(client.bearer().as_deref(), Some("rotated"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_error_hints() {
        assert!(
            ApiError::Status(403, String::new())
                .hint()
                .unwrap()
                .contains("RBAC")
        );
        assert!(ApiError::Status(401, String::new()).hint().is_some());
        assert!(ApiError::Status(500, String::new()).hint().is_none());
    }

    /// Self-signed test CA (`openssl req -x509 -newkey ec ...`), only parsed.
    const TEST_CA_PEM: &str = include_str!("testdata/ca.crt");
}
