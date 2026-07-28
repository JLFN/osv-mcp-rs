use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Simple in-memory cache entry with TTL.
struct CacheEntry {
    data: Value,
    expires_at: Instant,
}

/// HTTP client for the OSV.dev advisory database.
///
/// Results are cached in-memory with a configurable TTL (default 5 minutes)
/// to avoid redundant network calls during a session.
pub struct AdvisoryClient {
    client: Client,
    cache: Mutex<HashMap<String, CacheEntry>>,
    cache_ttl: Duration,
}

impl AdvisoryClient {
    /// Creates a new client.
    pub fn new() -> Self {
        Self {
            client: Client::builder()
                .timeout(Duration::from_secs(15))
                .user_agent("osv-mcp/1.2.0")
                .build()
                .expect("reqwest Client::builder() should never fail with these options"),
            cache: Mutex::new(HashMap::new()),
            cache_ttl: Duration::from_secs(300),
        }
    }

    /// Returns a cached value if it exists and hasn't expired.
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

    /// Search OSV.dev - covers GitHub Advisory, RustSec, PyPI, npm, Go, Maven, NuGet.
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

        let resp = self
            .client
            .post("https://api.osv.dev/v1/query")
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("OSV.dev query failed: {}", e))?;

        if !resp.status().is_success() {
            return Err(format!(
                "OSV.dev returned HTTP {}",
                resp.status().as_u16()
            ));
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
    pub async fn get_advisory_by_id(&self, id: &str) -> Result<Value, String> {
        let cache_key = format!("advisory:{}", id);
        if let Some(cached) = self.cache_get(&cache_key) {
            return Ok(cached);
        }

        let url = format!("https://api.osv.dev/v1/vulns/{}", id);
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

    /// Query OSV batch endpoint for multiple packages (lockfile mapping).
    pub async fn query_batch(
        &self,
        packages: Vec<(&str, &str, &str)>,
    ) -> Result<Value, String> {
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

        let resp = self
            .client
            .post("https://api.osv.dev/v1/querybatch")
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