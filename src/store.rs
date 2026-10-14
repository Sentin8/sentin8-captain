// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! `orch_services` registry stored in Valkey.
//!
//! Valkey data model:
//! - Key `captain:svc:{service_type}` — HASH, field = `{ip}:{port}`,
//! value = JSON blob of the instance.
//! - Pub/sub channel `captain:changed` — Captain PUBLISHes on any change,
//! consumers (Proxy, TLS) SUBSCRIBE to get push notifications.
//! - Advisory lock: `SETNX captain:lock:{ip}` with TTL.
//!
//! No PostgreSQL, no Auth, no mTLS token needed for the registry.

use glide::AsyncCommands;
use serde::{Deserialize, Serialize};

/// A service instance stored in Valkey.
#[derive(Debug, Clone, Serialize, Deserialize)]
/// The serviceinstance type.
pub struct ServiceInstance {
    /// Hash field key: `"{ip}:{port}"`.
    /// The key.
    pub key: String,
    /// The service type.
    pub service_type: String,
    /// The local ip.
    pub local_ip: String,
    /// The local port.
    pub local_port: u16,
    /// The pid.
    pub pid: u32,
    /// The start priority.
    pub start_priority: i16,
    /// The cpu avg 1m.
    pub cpu_avg_1m: f32,
    /// The memory avg 1m.
    pub memory_avg_1m: f32,
    /// Resident set size in MiB (1-minute rolling average).
    #[serde(default)]
    /// The rss mb avg 1m.
    pub rss_mb_avg_1m: f32,
    /// The latency avg 1m ms.
    pub latency_avg_1m_ms: f32,
    /// The last health check.
    pub last_health_check: Option<i64>, // unix timestamp
    /// The status.
    pub status: String,
    /// The restarts.
    pub restarts: i32,
    /// started time.
    pub started_at: Option<i64>, // unix timestamp
    /// Sentin8 platform version (workspace `CARGO_PKG_VERSION`).
    #[serde(default)]
    /// The version.
    pub version: String,
    /// Compile-time build hash (from the service's health payload `build`
    /// field — captured by the monitor). Shown as `{version}.{build_hash}`
    /// in `make status` / the Dash so operators can verify WHICH binary is
    /// actually running — a stale binary can silently serve. serde-default:
    /// older registry entries parse without it.
    #[serde(default)]
    /// The build hash.
    pub build_hash: String,
    /// Number of ERROR-level log events in the last window (from log metrics).
    #[serde(default)]
    /// The errors.
    pub errors: i64,
    /// Number of WARN-level log events in the last window (from log metrics).
    #[serde(default)]
    /// The warnings.
    pub warnings: i64,
    /// Number of inbound API calls (connections) in the last window
    /// (from proxy traffic metrics via the `stat:metrics:tls` channel).
    #[serde(default)]
    /// The API calls.
    pub api_calls: i64,
}

impl ServiceInstance {
    /// Handle valkey key.
    pub fn valkey_key(service_type: &str) -> String {
        format!("captain:svc:{service_type}")
    }

    /// Globally-unique instance key: `{service_type}/{ip}:{port}`.
    ///
    /// Used as the Valkey hash field, the CLI/display identifier, and the
    /// Handle make key.
    pub fn make_key(_service_type: &str, ip: &str, port: u16) -> String {
        format!("{ip}:{port}")
    }
}

/// Insert or replace an instance in Valkey and notify consumers.
/// Handle upsert instance.
pub async fn upsert_instance(
    conn: &glide::GlideClient,
    inst: &ServiceInstance,
) -> Result<(), glide::GlideError> {
    let key = ServiceInstance::valkey_key(&inst.service_type);
    let json = serde_json::to_string(inst).unwrap_or_default();
    let _: () = conn.hset(&key, &inst.key, &json).await?;
    let _: () = conn.publish("captain:changed", &inst.service_type).await?;
    Ok(())
}

/// Fetch a single instance by its registry identity — HASH
/// `captain:svc:{service_type}`, FIELD `{ip}:{port}` (the same shape
/// [`upsert_instance`] writes and every list helper reads). Returns `None`
/// when the service type has no row yet or the field is absent.
///
/// The tier gate (D6) MUST consult instances through this helper: a bare
/// `GET "{ip}:{port}"` reads a string key that NEVER exists (the registry
/// is hash-shaped), so the gate polled `nil` every second and degraded
/// every boot to its full timeout — five wasted 60s waits per boot.
pub async fn get_instance(
    conn: &glide::GlideClient,
    service_type: &str,
    make_key: &str,
) -> Result<Option<ServiceInstance>, glide::GlideError> {
    let key = ServiceInstance::valkey_key(service_type);
    let raw: Option<String> = conn.hget(&key, make_key).await?;
    Ok(raw.and_then(|json| serde_json::from_str(&json).ok()))
}

// ── Service-failure alerts (WARN-10: surfacing crash loops) ────────────

/// One service alert: a service that exhausted its restart budget (or any
/// other operator-actionable failure). Stored as HASH `captain:alerts`,
/// field `service_type` → JSON. The startup stream attaches them to its
/// progress payloads and the CLI prints them — a crash-looping service is
/// a FIRST-CLASS event, not a line in captain.log. Cleared when the
/// service next reaches `Active` (self-heal succeeded) and by the daily
/// display-counter reset.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ServiceAlert {
    /// The failed service type.
    pub service_type: String,
    /// Restart count at give-up (MAX_RESTARTS).
    pub restarts: i32,
    /// Why the operator must intervene — human-readable.
    pub reason: String,
    /// Where to look: the service's log path.
    pub log_path: String,
    /// Unix timestamp of the alert.
    pub at: i64,
}

fn alerts_key() -> &'static str {
    "captain:alerts"
}

/// Record a service alert (idempotent per service — the field overwrites).
pub async fn record_alert(
    conn: &glide::GlideClient,
    alert: &ServiceAlert,
) -> Result<(), glide::GlideError> {
    let json = serde_json::to_string(alert).unwrap_or_default();
    let _: () = conn.hset(alerts_key(), &alert.service_type, &json).await?;
    let _: () = conn.publish("captain:changed", "alert").await?;
    Ok(())
}

/// Clear the alert for a service (self-heal succeeded / operator action).
pub async fn clear_alert(
    conn: &glide::GlideClient,
    service_type: &str,
) -> Result<(), glide::GlideError> {
    let _: () = conn.hdel(alerts_key(), service_type).await?;
    Ok(())
}

/// List all active alerts as `(service_type, ServiceAlert)`.
pub async fn list_alerts(
    conn: &glide::GlideClient,
) -> Result<Vec<(String, ServiceAlert)>, glide::GlideError> {
    let entries: Vec<(String, String)> = conn.hgetall(alerts_key()).await?;
    Ok(entries
        .into_iter()
        .filter_map(|(svc, json)| serde_json::from_str(&json).ok().map(|a| (svc, a)))
        .collect())
}

/// List all instances for a given IP across all service types.
/// List for ip.
pub async fn list_for_ip(
    conn: &glide::GlideClient,
    local_ip: &str,
) -> Result<Vec<ServiceInstance>, glide::GlideError> {
    let mut all = Vec::new();
    let keys: Vec<String> = glide::cmd("KEYS")
        .arg("captain:svc:*")
        .query_async(conn)
        .await
        .unwrap_or_default();
    for key in keys {
        let entries: Vec<(String, String)> = conn.hgetall(&key).await.unwrap_or_default();
        for (_field, json) in entries {
            if let Ok(inst) = serde_json::from_str::<ServiceInstance>(&json) {
                if inst.local_ip == local_ip {
                    all.push(inst);
                }
            }
        }
    }
    all.sort_by_key(|i| (i.start_priority, i.local_port));
    Ok(all)
}

/// List all instances across all IPs (for the management API).
/// List all.
pub async fn list_all(
    conn: &glide::GlideClient,
) -> Result<Vec<ServiceInstance>, glide::GlideError> {
    let mut all = Vec::new();
    let keys: Vec<String> = glide::cmd("KEYS")
        .arg("captain:svc:*")
        .query_async(conn)
        .await
        .unwrap_or_default();
    for key in keys {
        let entries: Vec<(String, String)> = conn.hgetall(&key).await.unwrap_or_default();
        for (_field, json) in entries {
            if let Ok(inst) = serde_json::from_str::<ServiceInstance>(&json) {
                all.push(inst);
            }
        }
    }
    all.sort_by(|a, b| {
        a.service_type
            .cmp(&b.service_type)
            .then(a.local_ip.cmp(&b.local_ip))
    });
    Ok(all)
}

/// List all `Active` instances with a fresh health check for a given
/// service type (for consumers like Proxy, TLS). Only `Active` instances
/// are traffic-ready — `Started` is a transient state that is excluded.
#[allow(dead_code)]
/// List active for type.
pub async fn list_active_for_type(
    conn: &glide::GlideClient,
    service_type: &str,
) -> Result<Vec<ServiceInstance>, glide::GlideError> {
    let key = ServiceInstance::valkey_key(service_type);
    let entries: Vec<(String, String)> = conn.hgetall(&key).await.unwrap_or_default();
    let now = chrono::Utc::now().timestamp();
    let mut result = Vec::new();
    for (_field, json) in entries {
        if let Ok(inst) = serde_json::from_str::<ServiceInstance>(&json) {
            if inst.status == "Active" {
                if let Some(ts) = inst.last_health_check {
                    if now - ts < 30 {
                        result.push(inst);
                    }
                }
            }
        }
    }
    result.sort_by(|a, b| {
        a.local_ip
            .cmp(&b.local_ip)
            .then(a.local_port.cmp(&b.local_port))
    });
    Ok(result)
}

/// Update the status of an instance and notify.
///
/// **Important:** This also updates `last_health_check` to `now` so that
/// status transitions (e.g. Starting → Active) don't overwrite the fresh
/// timestamp that `update_metrics` just wrote. Without this, the proxy's
/// freshness filter (last_health_check < 30s) would reject the instance
/// even though it's Active.
async fn set_status(
    conn: &glide::GlideClient,
    inst: &ServiceInstance,
    status: &str,
) -> Result<(), glide::GlideError> {
    let mut inst = inst.clone();
    inst.status = status.to_string();
    inst.last_health_check = Some(chrono::Utc::now().timestamp());
    upsert_instance(conn, &inst).await
}

/// Mark an instance `Starting` and record the pid.
/// Handle mark starting.
pub async fn mark_starting(
    conn: &glide::GlideClient,
    inst: &ServiceInstance,
    pid: u32,
) -> Result<(), glide::GlideError> {
    let mut inst = inst.clone();
    inst.pid = pid;
    inst.status = "Starting".into();
    inst.started_at = Some(chrono::Utc::now().timestamp());
    upsert_instance(conn, &inst).await
}

/// Mark an instance `Started` (transient state — first healthy probe).
/// Currently unused: the monitor goes directly from `Starting` to `Active`
/// on the first healthy probe. Kept for future use (e.g. staged rollouts).
#[allow(dead_code)]
/// Handle mark started.
pub async fn mark_started(
    conn: &glide::GlideClient,
    inst: &ServiceInstance,
) -> Result<(), glide::GlideError> {
    set_status(conn, inst, "Started").await
}

/// Mark an instance `Active` (confirmed healthy — traffic-ready).
/// TLS and Proxy only send traffic to `Active` instances.
/// Handle mark active.
pub async fn mark_active(
    conn: &glide::GlideClient,
    inst: &ServiceInstance,
) -> Result<(), glide::GlideError> {
    set_status(conn, inst, "Active").await
}

/// Mark an instance `Inactive` (drain — TLS/Proxy stop sending new traffic).
/// Handle mark inactive.
pub async fn mark_inactive(
    conn: &glide::GlideClient,
    inst: &ServiceInstance,
) -> Result<(), glide::GlideError> {
    set_status(conn, inst, "Inactive").await
}

/// Update the 1-minute metric averages and `last_health_check`.
/// Update metrics.
pub async fn update_metrics(
    conn: &glide::GlideClient,
    inst: &ServiceInstance,
    cpu_avg_1m: f32,
    memory_avg_1m: f32,
    rss_mb_avg_1m: f32,
    latency_avg_1m_ms: f32,
) -> Result<(), glide::GlideError> {
    let mut inst = inst.clone();
    inst.cpu_avg_1m = cpu_avg_1m;
    inst.memory_avg_1m = memory_avg_1m;
    inst.rss_mb_avg_1m = rss_mb_avg_1m;
    inst.latency_avg_1m_ms = latency_avg_1m_ms;
    inst.last_health_check = Some(chrono::Utc::now().timestamp());
    upsert_instance(conn, &inst).await
}

/// Mark an instance `Killed` and increment `restarts`, returning the
/// UPDATED instance (captain DESIGN §8 invariant 10): the monitor's
/// snapshot predates the increment, so callers that respawn from the
/// snapshot would re-seed the counter with the pre-increment value —
/// the count never grew, `MAX_RESTARTS` was unreachable, and a boot
/// panic crash-looped a service every ~6s indefinitely (21k spawns,
/// zero give-up alerts).
/// Handle mark killed.
pub async fn mark_killed(
    conn: &glide::GlideClient,
    inst: &ServiceInstance,
) -> Result<ServiceInstance, glide::GlideError> {
    let mut inst = inst.clone();
    inst.status = "Killed".into();
    inst.pid = 0;
    inst.restarts += 1;
    upsert_instance(conn, &inst).await?;
    Ok(inst)
}

/// Mark an instance `Stopping`.
/// Handle mark stopping.
pub async fn mark_stopping(
    conn: &glide::GlideClient,
    inst: &ServiceInstance,
) -> Result<(), glide::GlideError> {
    set_status(conn, inst, "Stopping").await
}

/// Mark an instance `Stopped` (clean exit).
/// Handle mark stopped.
pub async fn mark_stopped(
    conn: &glide::GlideClient,
    inst: &ServiceInstance,
) -> Result<(), glide::GlideError> {
    let mut inst = inst.clone();
    inst.status = "Stopped".into();
    inst.pid = 0;
    upsert_instance(conn, &inst).await
}

/// Reset `restarts` to 0.
/// Handle reset restarts.
pub async fn reset_restarts(
    conn: &glide::GlideClient,
    inst: &ServiceInstance,
) -> Result<(), glide::GlideError> {
    let mut inst = inst.clone();
    inst.restarts = 0;
    upsert_instance(conn, &inst).await
}

/// Reset the per-day display counters — `restarts`, `errors`, and
/// `warnings` — to 0 for every instance owned by this captain (on
/// `local_ip`). Called once per day by the monitor's daily-reset task so
/// that the `RST`/`ERR`/`WRN` columns in `make status` show a rolling
/// 24-hour window rather than lifetime totals.
///
/// `api_calls` is **not** reset here — it is overwritten every 60s by the
/// traffic metrics subscriber from Stat's `stat:rollups:day`
/// channel, which already provides a true rolling 24-hour aggregate.
///
/// `restarts` is safe to reset here: the self-healing logic treats it as
/// a consecutive-restart counter and already zeroes it after a healthy
/// cooldown (`reset_restarts`), so a daily reset is just a wider bound.
/// Handle reset daily counters.
pub async fn reset_daily_counters(
    conn: &glide::GlideClient,
    local_ip: &str,
) -> Result<usize, glide::GlideError> {
    let instances = list_for_ip(conn, local_ip).await?;
    let mut count = 0usize;
    for inst in &instances {
        if inst.restarts == 0 && inst.errors == 0 && inst.warnings == 0 {
            continue;
        }
        let mut inst = inst.clone();
        inst.restarts = 0;
        inst.errors = 0;
        inst.warnings = 0;
        upsert_instance(conn, &inst).await?;
        count += 1;
    }
    Ok(count)
}

/// Update the version + build hash on an instance (captured from the
/// service's health endpoint by the monitor). Only writes if the value
/// differs from what's already stored (avoids unnecessary Valkey writes).
///
/// Read-modify-write: the caller's `inst` may be a stale snapshot (the
/// monitor holds the pre-tick record while `update_metrics` just wrote
/// fresh averages), so re-read the stored entry and change only `version`
/// / `build_hash` on it — writing the caller's snapshot wholesale would
/// clobber the metrics. (Surfaced by the TEST-3 registry roundtrip test.)
/// Update version build.
pub async fn update_version_build(
    conn: &glide::GlideClient,
    inst: &ServiceInstance,
    version: Option<&str>,
    build: Option<&str>,
) -> Result<(), glide::GlideError> {
    // CAPTAIN-4: store both the version and the build hash so `make
    // status`/Dash can show `{version}.{build_hash}` — verifying WHICH
    // binary is running requires both.
    let version = version.unwrap_or("");
    let build_hash = build.unwrap_or("");
    if inst.version == version && inst.build_hash == build_hash {
        return Ok(()); // already up to date
    }
    let all = list_for_ip(conn, &inst.local_ip).await?;
    let current = match all.iter().find(|i| i.key == inst.key) {
        Some(fresh) => fresh.clone(),
        None => return Ok(()), // entry removed meanwhile — nothing to update
    };
    let mut inst = current;
    inst.version = version.to_string();
    inst.build_hash = build_hash.to_string();
    upsert_instance(conn, &inst).await
}

/// **Overwrite** the error/warning counts for all instances of a service
/// type on a given IP. Called by the rollup metrics subscriber when
/// Stat publishes a rolling 24-hour snapshot to
/// `stat:rollups:day`. The snapshot is authoritative — it is not a
/// delta — so the stored value is replaced, not accumulated.
/// Handle set error warning counts.
pub async fn set_error_warning_counts(
    conn: &glide::GlideClient,
    local_ip: &str,
    service_type: &str,
    errors: i64,
    warnings: i64,
) -> Result<(), glide::GlideError> {
    let instances = list_for_ip(conn, local_ip).await?;
    for inst in &instances {
        if inst.service_type != service_type {
            continue;
        }
        if inst.errors == errors && inst.warnings == warnings {
            continue;
        }
        let mut inst = inst.clone();
        inst.errors = errors;
        inst.warnings = warnings;
        upsert_instance(conn, &inst).await?;
    }
    Ok(())
}

/// Set the inbound API call count for all instances of a given service
/// type on a given IP. Called by the traffic metrics subscriber when
/// Stat publishes a `stat:rollups:day` aggregate containing the
/// `proxy.traffic.{from}→{service}.count` rolling 24-hour value. The
/// count is **overwritten** (not accumulated) because the embedded
/// worker already aggregates over the full day window, so each rollup
/// message carries the authoritative 24-hour total.
/// Handle set API calls.
pub async fn set_api_calls(
    conn: &glide::GlideClient,
    local_ip: &str,
    service_type: &str,
    call_count: i64,
) -> Result<(), glide::GlideError> {
    let instances = list_for_ip(conn, local_ip).await?;
    for inst in &instances {
        if inst.service_type != service_type {
            continue;
        }
        // Skip the write if the value is already correct (avoids
        // unnecessary Valkey HSET + captain:changed publishes every 60s).
        if inst.api_calls == call_count {
            continue;
        }
        let mut inst = inst.clone();
        inst.api_calls = call_count;
        upsert_instance(conn, &inst).await?;
    }
    Ok(())
}

/// Count instances of a service type on this IP.
/// Handle count for type on ip.
pub async fn count_for_type_on_ip(
    conn: &glide::GlideClient,
    service_type: &str,
    local_ip: &str,
) -> Result<i64, glide::GlideError> {
    let instances = list_active_for_type(conn, service_type).await?;
    Ok(instances.iter().filter(|i| i.local_ip == local_ip).count() as i64)
}

/// Try to acquire an advisory lock using Valkey SET with NX + TTL.
///
/// If the lock is held but the PID stored in it is no longer alive,
/// the lock is stolen (deleted and re-acquired). This handles the case
/// where captain was killed (SIGKILL/crash) and couldn't release the lock.
/// Handle try advisory lock.
pub async fn try_advisory_lock(
    conn: &glide::GlideClient,
    local_ip: &str,
) -> Result<bool, glide::GlideError> {
    let key = format!("captain:lock:{local_ip}");
    let pid = std::process::id().to_string();

    // First, check if a stale lock is held by a dead process.
    if let Ok(Some(existing_pid_str)) = conn.get::<String, Option<String>>(key.clone()).await {
        if let Ok(existing_pid) = existing_pid_str.parse::<u32>() {
            if existing_pid != 0 && !crate::procfs::pid_alive(existing_pid) {
                tracing::warn!(
                    existing_pid,
                    "advisory lock held by dead process — stealing lock"
                );
                let _: () = conn.del(&key).await?;
            }
        }
    }

    // Try to acquire the lock (30s TTL — short enough to auto-expire
    // if captain crashes, long enough for a clean restart).
    let result: Option<String> = glide::cmd("SET")
        .arg(&key)
        .arg(&pid)
        .arg("NX")
        .arg("EX")
        .arg(30) // 30s TTL
        .query_async(conn)
        .await?;
    Ok(result.is_some())
}

/// Release the advisory lock.
/// Handle release advisory lock.
pub async fn release_advisory_lock(
    conn: &glide::GlideClient,
    local_ip: &str,
) -> Result<(), glide::GlideError> {
    let key = format!("captain:lock:{local_ip}");
    let _: () = conn.del(&key).await?;
    Ok(())
}

/// Remove all instances in terminal states (Stopped, Killed) for this IP.
/// Called at startup to clear stale entries from a previous captain run.
/// Handle cleanup terminal states.
pub async fn cleanup_terminal_states(
    conn: &glide::GlideClient,
    local_ip: &str,
) -> Result<usize, glide::GlideError> {
    let instances = list_for_ip(conn, local_ip).await?;
    let mut removed = 0;
    for inst in &instances {
        if inst.status == "Stopped" || inst.status == "Killed" {
            let key = ServiceInstance::valkey_key(&inst.service_type);
            let _: () = conn.hdel(&key, &inst.key).await?;
            removed += 1;
        }
    }
    Ok(removed)
}

/// Delete a single instance from Valkey and notify consumers.
/// Called after an instance reaches a terminal state (Stopped or Killed)
/// so that its port is freed for reuse and `sentin8 captain services` no longer
/// shows the stale entry.
/// Delete instance.
pub async fn delete_instance(
    conn: &glide::GlideClient,
    inst: &ServiceInstance,
) -> Result<(), glide::GlideError> {
    let key = ServiceInstance::valkey_key(&inst.service_type);
    let _: () = conn.hdel(&key, &inst.key).await?;
    let _: () = conn.publish("captain:changed", &inst.service_type).await?;
    Ok(())
}
