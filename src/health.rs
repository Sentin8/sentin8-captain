// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Health probes for supervised services.
//!
//! Always probes `https://{sni_host}:{port}{health_path}` — all managed
//! services terminate TLS directly. Certificate verification is
//! **disabled** because Captain pins DNS resolution to the instance IP
//! via `resolve`, so the connection goes directly to the instance
//! (bypassing Sentin8:TLS proxy). The certificate presented by the
//! instance may be self-signed or issued for a different hostname, so
//! strict verification would fail.
//!
//! A 2xx response within the timeout is healthy.
//!
//! Probe clients are cached per target (a process-lifetime map keyed by
//! target + timeout) and keep **default connection pooling**: the
//! TCP+TLS session stays warm across monitor ticks, so the probe RTT is
//! the true request latency (sub-ms loopback) instead of a
//! post-quantum handshake cost (~40 ms — X25519MLKEM768 + ML-DSA-65).
//! Only a cache miss (e.g. after a service restart) pays the handshake,
//! amortized by the 6-sample rolling average.
//!
//! A pooled connection can outlive a service respawn (SIGKILL + re-bind
//! on the same port) and surfaces as a stale RST/timeout — the CAPT-6
//! kill spiral. The stale-connection class is handled by **retry-once**:
//! the first transport failure discards the idle pool and the probe
//! retries once on a FRESH connection; only the successful attempt's
//! RTT is sampled. Three consecutive failures therefore require an
//! endpoint that is genuinely unreachable across a full retry, never a
//! single stale-connection artifact.
//!
//! RTT is measured with microsecond precision (`as_micros / 1000.0`):
//! warm-connection probes are sub-1ms and integer `as_millis` would
//! floor them to 0, losing all resolution in `latency_avg_1m_ms`.
//! Cold connects additionally report the handshake phase separately
//! (`handshake_ms`) so the metric stays interpretable while the first
//! post-restart sample amortizes.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Result of a health probe.
#[derive(Debug, Clone)]
/// The healthprobe type.
pub struct HealthProbe {
    /// The ok.
    pub ok: bool,
    /// The latency ms.
    pub latency_ms: f32,
    #[allow(dead_code)]
    /// The status code.
    pub status_code: Option<u16>,
    /// The failure mode when `ok == false` (transport error string, empty
    /// on success) — the monitor logs it so a kill decision is auditable.
    pub error: String,
    /// Version reported by the service's health endpoint (if present).
    /// The version.
    pub version: Option<String>,
    /// Build hash reported by the service's health endpoint (if present).
    /// The build.
    pub build: Option<String>,
    /// In-flight connection gauge reported by the service's health endpoint
    /// (`active_connections`, captain README §7) — `None` when the payload does not
    /// carry the field (non-gauge service; drain falls back to the fixed
    /// window). Consumed by `supervisor::drain_until_idle`
    /// (captain README §7).
    /// The active connections.
    pub active_connections: Option<u64>,
    /// TLS handshake time when this probe established a FRESH
    /// connection (cache miss or the retry-after-stale-conn path);
    /// `None` on a warm pooled connection — the RTT is then pure
    /// request latency. CAPT-7: keeps `latency_avg_1m_ms` interpretable
    /// while post-restart handshake samples amortize.
    pub handshake_ms: Option<f32>,
}
/// hostname is the service's domain name and the TCP connection goes
/// directly to the instance, NOT through the proxy.
///
/// When `use_http` is true (e.g. acme — a bootstrap service that
/// serves plain HTTP), the probe uses HTTP instead of HTTPS.
///
/// `service_type` is the service identity (e.g. `sentin8:bus`,
/// `hotel8:pms`, `bank8:payments:worker` — colon form). The SNI
/// hostname uses the DNS label: the identity is converted to its dash
/// form and stripped of the `sentin8-` prefix for platform services
/// (e.g. `sentin8:bus` → `bus`, `bank8:pms` → `bank8-pms`). Workers
/// keep their base identity's label + `-worker` suffix so they get a
/// distinct SNI (`bank8:payments:worker` → `bank8-payments-worker`).
///
/// Process-lifetime cache of probe clients, keyed by
/// `(use_http, sni_host, socket_addr, timeout_ms)`. Reusing one
/// `reqwest::Client` per probe target lets its connection pool keep the
/// TCP+TLS session warm between monitor ticks — see the module doc.
fn probe_clients() -> &'static Mutex<HashMap<String, reqwest::Client>> {
    static CLIENTS: OnceLock<Mutex<HashMap<String, reqwest::Client>>> = OnceLock::new();
    CLIENTS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Handle probe.
pub async fn probe(
    local_ip: &str,
    local_port: u16,
    health_path: &str,
    timeout_ms: u64,
    service_type: &str,
    use_http: bool,
) -> HealthProbe {
    let sentin8_domain =
        std::env::var("SENTIN8_DOMAIN").unwrap_or_else(|_| "sentin8.local".to_string());
    // Derive the DNS label from the colon identity : convert to the
    // dash form first (`bank8:payments:worker` → `bank8-payments-worker`),
    // then strip the vertical prefix for sentin8 services
    // ("sentin8-auth" → "auth", but "bank8-ledger" stays "bank8-ledger").
    let service_label = sentin8::config::service_dash_form(service_type);
    let service_label = service_label
        .strip_prefix("sentin8-")
        .unwrap_or(&service_label);
    let sni_host = format!("{service_label}.ops.sys.{sentin8_domain}");
    let socket_addr = std::net::SocketAddr::from((
        local_ip
            .parse::<std::net::IpAddr>()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        local_port,
    ));

    let url = if use_http {
        format!("http://{local_ip}:{local_port}{health_path}")
    } else {
        format!("https://{sni_host}:{local_port}{health_path}")
    };

    // Cached probe client per target (see module doc). The cache key pins
    // the resolve target and timeout, which are fixed per service type;
    // a new key only appears for a new target (port move / restart).
    let cache_key = format!("{use_http}|{sni_host}|{socket_addr}|{timeout_ms}");

    // CAPT-7 retry-once: a stale pooled connection (outlived a service
    // respawn, SIGKILL + re-bind on the same port) surfaces as a transport
    // error on the first send. The CAPT-6 fix paid a fresh connection per
    // probe to avoid ever touching the pool; the target-state fix keeps
    // the warm session and retries ONCE on a FRESH client when the pooled
    // send fails — a healthy endpoint with a stale pool cannot accumulate
    // consecutive failures, and only the successful attempt's RTT is
    // sampled (a stale-RST costs zero in `latency_avg_1m_ms`).
    let mut attempt = 0u32;
    loop {
        // Attempt 0 rides the warm pooled client (cache hit, or a fresh
        // build on first-ever probe of the target); attempt 1 always
        // builds a fresh client (empty pool → guaranteed-new TCP+TLS)
        // and caches it so subsequent ticks keep the new session warm.
        let cached = if attempt == 0 {
            probe_clients().lock().unwrap().get(&cache_key).cloned()
        } else {
            None
        };
        let fresh_conn = cached.is_none();
        let client = match cached {
            Some(c) => c,
            None => match reqwest::Client::builder()
                .timeout(Duration::from_millis(timeout_ms))
                .pool_idle_timeout(Duration::from_secs(30))
                .resolve(&sni_host, socket_addr)
                .build()
            {
                Ok(c) => c,
                Err(_) => {
                    return HealthProbe {
                        ok: false,
                        latency_ms: 0.0,
                        handshake_ms: None,
                        status_code: None,
                        error: "probe client build failed".to_string(),
                        version: None,
                        build: None,
                        active_connections: None,
                    }
                }
            },
        };
        if fresh_conn {
            if let Ok(mut cache) = probe_clients().lock() {
                cache.insert(cache_key.clone(), client.clone());
            }
        }

        let start = Instant::now();
        match client.get(&url).send().await {
            Ok(resp) => {
                // Micros → fractional ms: sub-1ms warm-connection probes must
                // not truncate to 0.0 (CAPTAIN-8).
                let latency_ms = start.elapsed().as_micros() as f32 / 1000.0;
                let code = resp.status().as_u16();
                let ok = (200..300).contains(&code);
                let body: serde_json::Value = if ok {
                    resp.json().await.unwrap_or(serde_json::Value::Null)
                } else {
                    serde_json::Value::Null
                };
                let (version, build) = if ok {
                    (
                        body.get("version")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                        body.get("build")
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string()),
                    )
                } else {
                    (None, None)
                };
                // Drain gauge (captain README §7): capture the optional `active_connections` —
                // None when absent (non-gauge service) so the drain falls back to
                // the fixed window instead of treating a missing key as zero.
                let active_connections = if ok {
                    body.get("active_connections").and_then(|v| v.as_u64())
                } else {
                    None
                };
                // CAPT-7 observability: on a freshly-built client the RTT includes
                // TCP connect + PQ TLS handshake (cache miss / post-retry). Report
                // the phase split so `latency_avg_1m_ms` stays interpretable while
                // the first post-restart sample amortizes; warm attempts carry None
                // (pure request latency).
                return HealthProbe {
                    ok,
                    latency_ms,
                    handshake_ms: if fresh_conn { Some(latency_ms) } else { None },
                    status_code: Some(code),
                    error: if ok {
                        String::new()
                    } else {
                        format!("non-2xx status {code}")
                    },
                    version,
                    build,
                    active_connections,
                };
            }
            Err(probe_err) if attempt == 0 => {
                attempt = 1;
                // Debug-level: probe failures feed the kill branch (3 consecutive →
                // SIGKILL); a misdiagnosed failure is invisible without the error
                // string. Warn only for repeated failures would hide the pattern —
                // debug keeps the firehose quiet while carrying the failure mode.
                tracing::debug!(
                    port = local_port,
                    url = %url,
                    error = %probe_err,
                    attempt = 1,
                    "health probe transport error — retrying once on a fresh connection (CAPT-7)"
                );
            }
            Err(probe_err) => {
                tracing::debug!(
                    port = local_port,
                    url = %url,
                    error = %probe_err,
                    attempt = 2,
                    "health probe failed (fresh connection too)"
                );
                return HealthProbe {
                    ok: false,
                    latency_ms: start.elapsed().as_micros() as f32 / 1000.0,
                    handshake_ms: None,
                    status_code: None,
                    error: probe_err.to_string(),
                    version: None,
                    build: None,
                    active_connections: None,
                };
            }
        }
    }
}
