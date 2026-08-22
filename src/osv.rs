//! HTTP client for the OSV.dev vulnerability database.
//!
//! Wraps the OSV.dev REST API (`api.osv.dev`) with an in-memory TTL cache so
//! repeated queries within a session do not hit the network again. The base
//! URL is injectable so the client can be tested against an in-process mock
//! server.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use reqwest::Client;
use serde_json::{json, Value};

/// In-memory cache entry with a time-to-live.
#[derive(Debug)]
struct CacheEntry {
    data: Value,
    expires_at: Instant,
}

/// HTTP client for the OSV.dev advisory database.
///
/// Results are cached in-memory with a configurable TTL (default 5 minutes)
/// to avoid redundant network calls during a session.
#[derive(Debug)]
pub struct OsvClient {
    client: Client,
    base_url: String,
    cache: Mutex<HashMap<String, CacheEntry>>,
    cache_ttl: Duration,
}

impl OsvClient {
    /// Create a client pointed at the public OSV.dev API.
    pub fn new() -> Self {
        Self::with_base_url("https://api.osv.dev".to_string())
    }

    /// Create a client pointed at an arbitrary base URL (used by tests).
    fn with_base_url(base_url: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(15))
                .user_agent(format!("osv-mcp/{}", env!("CARGO_PKG_VERSION")))
                .build()
                .expect("reqwest Client::builder() should never fail with these options"),
            base_url,
            cache: Mutex::new(HashMap::new()),
            cache_ttl: Duration::from_secs(300),
        }
    }

    /// Returns a cached value if it exists and has not expired.
    fn cache_get(&self, key: &str) -> Option<Value> {
        let cache = self.cache.lock().ok()?;
        if let Some(entry) = cache.get(key) {
            if entry.expires_at > Instant::now() {
                return Some(entry.data.clone());
            }
        }
        None
    }

    /// Stores a value in the cache.
    fn cache_set(&self, key: String, value: Value) {
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(
                key,
                CacheEntry {
                    data: value,
                    expires_at: Instant::now() + self.cache_ttl,
                },
            );
        }
    }

    /// Search OSV.dev — covers GitHub Advisory, RustSec, PyPI, npm, Go,
    /// Maven, NuGet. Returns a JSON document with an `advisories` array
    /// (id, summary, severity, aliases, affected packages) and a `count`.
    pub async fn search_osv(
        &self,
        package: Option<&str>,
        ecosystem: Option<&str>,
        query: Option<&str>,
    ) -> Result<Value, String> {
        let cache_key = format!(
            "search:{}:{}:{}",
            package.unwrap_or(""),
            ecosystem.unwrap_or(""),
            query.unwrap_or("")
        );
        if let Some(cached) = self.cache_get(&cache_key) {
            return Ok(cached);
        }

        let mut body = json!({});
        if let Some(pkg) = package {
            body["package"] = json!({"name": pkg});
            if let Some(eco) = ecosystem {
                body["package"]["ecosystem"] = json!(eco);
            }
        }
        if let Some(q) = query {
            if package.is_none() {
                body["package"] = json!({"name": q});
            }
        }

        let url = format!("{}/v1/query", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("OSV.dev query failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!("OSV.dev returned HTTP {}", resp.status().as_u16()));
        }

        let data: Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse OSV.dev response: {}", e))?;

        let vulns: Vec<Value> = data["vulns"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .map(|v| {
                        json!({
                            "id": v["id"],
                            "summary": v["summary"],
                            "severity": v["database_specific"]["severity"].as_str()
                                .or(v["severity"].as_array()
                                    .and_then(|a| a.first())
                                    .and_then(|s| s["score"].as_str()))
                                .unwrap_or("unknown"),
                            "published": v["published"],
                            "modified": v["modified"],
                            "aliases": v["aliases"],
                            "affected": v["affected"].as_array().map(|a| {
                                a.iter().map(|af| json!({
                                    "package": af["package"]["name"],
                                    "ecosystem": af["package"]["ecosystem"],
                                    "ranges": af["ranges"],
                                })).collect::<Vec<_>>()
                            }),
                            "source": "osv.dev",
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let result = json!({"advisories": vulns, "count": vulns.len()});
        self.cache_set(cache_key, result.clone());
        Ok(result)
    }

    /// Get a specific advisory by ID (CVE-*, GHSA-*, RUSTSEC-*, OSV-*).
    /// Returns a curated JSON record: id, summary, details, aliases,
    /// severity, affected packages and ranges, references, and a source URL.
    pub async fn get_advisory_by_id(&self, id: &str) -> Result<Value, String> {
        let cache_key = format!("advisory:{}", id);
        if let Some(cached) = self.cache_get(&cache_key) {
            return Ok(cached);
        }

        let url = format!("{}/v1/vulns/{}", self.base_url, id);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("OSV.dev lookup failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!(
                "Advisory not found: {} (HTTP {})",
                id,
                resp.status().as_u16()
            ));
        }

        let v: Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse advisory response: {}", e))?;

        let result = json!({
            "id": v["id"],
            "summary": v["summary"],
            "details": v["details"],
            "aliases": v["aliases"],
            "severity": v["severity"],
            "published": v["published"],
            "modified": v["modified"],
            "references": v["references"].as_array().map(|refs| {
                refs.iter().map(|r| json!({"type": r["type"], "url": r["url"]})).collect::<Vec<_>>()
            }),
            "affected": v["affected"].as_array().map(|a| {
                a.iter().map(|af| json!({
                    "package": af["package"]["name"],
                    "ecosystem": af["package"]["ecosystem"],
                    "ranges": af["ranges"],
                    "versions": af["versions"],
                })).collect::<Vec<_>>()
            }),
            "source": "osv.dev",
            "source_url": format!("https://osv.dev/vulnerability/{}", v["id"].as_str().unwrap_or(id)),
        });

        self.cache_set(cache_key, result.clone());
        Ok(result)
    }

    /// Query the OSV batch endpoint for multiple packages (used for lockfile
    /// mapping). `packages` is a list of `(name, ecosystem, version)`.
    /// Returns the raw batch response (`{"results": [...]}`).
    pub async fn query_batch(&self, packages: Vec<(&str, &str, &str)>) -> Result<Value, String> {
        let cache_key = format!("batch:{}", {
            let mut s = String::new();
            for (n, e, v) in &packages {
                s.push_str(&format!("{}@{}:{},", n, v, e));
            }
            s
        });
        if let Some(cached) = self.cache_get(&cache_key) {
            return Ok(cached);
        }

        let queries: Vec<Value> = packages
            .iter()
            .map(|(name, ecosystem, version)| {
                json!({"package": {"name": name, "ecosystem": ecosystem}, "version": version})
            })
            .collect();

        let url = format!("{}/v1/querybatch", self.base_url);
        let resp = self
            .client
            .post(&url)
            .json(&json!({"queries": queries}))
            .send()
            .await
            .map_err(|e| format!("OSV.dev batch query failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!(
                "OSV.dev batch returned HTTP {}",
                resp.status().as_u16()
            ));
        }

        let data: Value = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse batch response: {}", e))?;

        self.cache_set(cache_key, data.clone());
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn an in-process HTTP server that answers every request with the
    /// given canned body. Returns the base URL the client should use.
    async fn spawn_mock_server(body: &'static str) -> String {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock server");
        let addr = listener.local_addr().expect("local addr");
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            // Read the request head; the exact bytes do not matter for the
            // canned response.
            let mut buf = [0u8; 4096];
            let mut read = 0usize;
            while read < buf.len() {
                let n = socket.read(&mut buf[read..]).await.unwrap_or(0);
                if n == 0 {
                    break;
                }
                read += n;
                if buf[..read].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = socket.write_all(resp.as_bytes()).await;
            let _ = socket.shutdown().await;
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn test_search_osv_parses_vulns() {
        let base = spawn_mock_server(
            r#"{"vulns":[{"id":"GHSA-xxxx-xxxx-xxxx","summary":"a summary","severity":[{"score":"8.1"}],"affected":[{"package":{"name":"hyper","ecosystem":"crates.io"}}]}]}"#,
        )
        .await;
        let client = OsvClient::with_base_url(base);

        let result = client
            .search_osv(Some("hyper"), Some("crates.io"), None)
            .await
            .expect("search should succeed");

        assert_eq!(result["count"], 1);
        assert_eq!(result["advisories"][0]["id"], "GHSA-xxxx-xxxx-xxxx");
        assert_eq!(result["advisories"][0]["severity"], "8.1");
        assert_eq!(result["advisories"][0]["affected"][0]["package"], "hyper");
    }

    #[tokio::test]
    async fn test_search_osv_caches_second_call() {
        let base = spawn_mock_server(r#"{"vulns":[{"id":"CVE-2024-0001"}]}"#).await;
        let client = OsvClient::with_base_url(base);

        let first = client.search_osv(None, None, Some("tokio")).await;
        let second = client.search_osv(None, None, Some("tokio")).await;
        assert_eq!(first.expect("first call"), second.expect("second call"));
        // The mock server only accepts one connection; a second network call
        // would hang and time out, so success of the second call proves the
        // cache served it.
    }

    #[tokio::test]
    async fn test_get_advisory_by_id_parses_record() {
        let base = spawn_mock_server(
            r#"{"id":"RUSTSEC-2021-0079","summary":"denial of service","aliases":["CVE-2021-0001"],"affected":[{"package":{"name":"hyper","ecosystem":"crates.io"},"ranges":[{"events":[{"fixed":"0.14.17"}]}]}]}"#,
        )
        .await;
        let client = OsvClient::with_base_url(base);

        let result = client
            .get_advisory_by_id("RUSTSEC-2021-0079")
            .await
            .expect("lookup should succeed");

        assert_eq!(result["id"], "RUSTSEC-2021-0079");
        assert_eq!(result["aliases"][0], "CVE-2021-0001");
        assert_eq!(
            result["affected"][0]["ranges"][0]["events"][0]["fixed"],
            "0.14.17"
        );
        assert!(result["source_url"]
            .as_str()
            .unwrap()
            .contains("RUSTSEC-2021-0079"));
    }

    #[tokio::test]
    async fn test_query_batch_parses_results() {
        let base =
            spawn_mock_server(r#"{"results":[{"vulns":[{"id":"CVE-2024-0001"}]},{"vulns":[]}]}"#)
                .await;
        let client = OsvClient::with_base_url(base);

        let result = client
            .query_batch(vec![
                ("hyper", "crates.io", "0.14.0"),
                ("serde", "crates.io", "1.0.200"),
            ])
            .await
            .expect("batch should succeed");

        let results = result["results"].as_array().expect("results array");
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["vulns"][0]["id"], "CVE-2024-0001");
        assert!(results[1]["vulns"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_get_advisory_error_on_non_success() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = [0u8; 4096];
            let _ = socket.read(&mut buf).await;
            let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            let _ = socket.write_all(resp.as_bytes()).await;
        });
        let client = OsvClient::with_base_url(format!("http://{}", addr));

        let err = client
            .get_advisory_by_id("CVE-2099-9999")
            .await
            .expect_err("should fail on 404");
        assert!(err.contains("Advisory not found"), "got: {err}");
    }
}
