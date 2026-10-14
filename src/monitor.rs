// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Monitor loop — runs every `monitor_tick_s` seconds. For each owned row
//! (`local_ip = SENTIN8_CAPTAIN_LOCAL_IP`) it samples CPU/memory, probes health,
//! updates the row's metrics, transitions status, and triggers
//! self-healing when a process is dead or unresponsive.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::Duration;

use crate::config::CaptainConfig;
use crate::{health, procfs, store, supervisor};

/// Global shutdown flag — when true, the monitor loop stops self-healing
/// (spawning new instances) so `shutdown_all_services` can bring everything
/// down without the monitor fighting it.
static SHUTTING_DOWN: AtomicBool = AtomicBool::new(false);

/// Called by the server on graceful shutdown to suppress self-healing.
/// Handle set shutting down.
pub fn set_shutting_down() {
    SHUTTING_DOWN.store(true, Ordering::SeqCst);
}

/// Check whether a rolling upgrade is in progress for a given instance key.
///
/// The upgrade publishes progress under BOTH identities (captain DESIGN §8
/// invariant 9): the OLD instance's key (`captain:upgrade:{ip}:{port}`) and
/// the spawned NEW instance's key (`captain:upgrade:new:{ip}:{port}`). The
/// guard checks both — matching only the old key left the flapping new
/// instance unshielded, and the monitor respawned it every tick through the
/// whole upgrade. If either key exists, the monitor must NOT self-heal the
/// instance — the upgrade's abort path handles cleanup.
/// Handle is upgrade in progress.
pub async fn is_upgrade_in_progress(conn: &glide::GlideClient, key: &str) -> bool {
    let upgrade_key = format!("captain:upgrade:{key}");
    let new_upgrade_key = format!("captain:upgrade:new:{key}");
    let old_val: Option<String> = glide::cmd("GET")
        .arg(&upgrade_key)
        .query_async(conn)
        .await
        .unwrap_or(None);
    if old_val.is_some() {
        return true;
    }
    let new_val: Option<String> = glide::cmd("GET")
        .arg(&new_upgrade_key)
        .query_async(conn)
        .await
        .unwrap_or(None);
    new_val.is_some()
}

/// Per-instance rolling window for CPU, memory, and latency.
/// 6 samples at the monitor tick — set `SENTIN8_CAPTAIN_MONITOR_TICK_S=10`
/// for a literal 1-minute window.
#[derive(Debug, Clone, Default)]
/// The rollingwindow type.
pub struct RollingWindow {
    /// The cpu.
    pub cpu: Vec<f32>,
    /// The mem.
    pub mem: Vec<f32>,
    /// The rss mb.
    pub rss_mb: Vec<f32>,
    /// The latency.
    pub latency: Vec<f32>,
    /// Consecutive health-probe failures (live process).
    /// The consecutive failures.
    pub consecutive_failures: u32,
    /// Ticks since the instance became `Active` (for cooldown reset).
    /// The started ticks.
    pub started_ticks: u32,
    /// The most recent probe failure mode (empty when healthy) — rides the
    /// kill log so a kill decision is auditable (probe timeout vs
    /// connection refusal vs non-2xx).
    pub last_probe_error: String,
}

const WINDOW_SIZE: usize = 6;

fn windows() -> &'static Mutex<HashMap<String, RollingWindow>> {
    static W: OnceLock<Mutex<HashMap<String, RollingWindow>>> = OnceLock::new();
    W.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Spawn the monitor loop as a background task. Returns immediately.
/// Spawn it.
pub fn spawn(
    conn: glide::GlideClient,
    config: CaptainConfig,
    live_catalog: Arc<RwLock<HashMap<String, crate::catalog::ServiceCatalogEntry>>>,
) {
    // Spawn the rollup metrics subscriber — listens to `stat:rollups:day`
    // on Valkey and updates both API call counts and error/warning counts
    // on service instances. Stat's embedded worker aggregates raw metrics
    // from services (stat:metrics:tls for traffic, stat:metrics:log for
    // errors/warnings) into rolling 24-hour rollups, and captain consumes
    // the aggregated rollups rather than subscribing to raw channels.
    spawn_rollup_metrics_subscriber(conn.clone(), config.clone(), live_catalog.clone());

    // Spawn the daily-reset task — zeroes the `restarts`/`errors`/
    // `warnings`/`api_calls` display counters once per day at 00:00 UTC
    // so `make status` shows a rolling 24-hour window.
    spawn_daily_reset(conn.clone(), config.clone());
    // CAPT-ALERT-2: slow last-resort respawn for services parked at
    // give-up (the alert stays raised; Active clears it).
    spawn_last_resort_respawner(conn.clone(), config.clone(), live_catalog.clone());

    tokio::spawn(async move {
        let tick = Duration::from_secs(config.monitor_tick_s.max(1));
        let health_probe_failures = config.health_probe_failures.max(1);
        let cooldown_reset_s = config.cooldown_reset_s.max(1);
        loop {
            if SHUTTING_DOWN.load(Ordering::SeqCst) {
                tracing::info!("monitor: shutting down — exiting monitor loop");
                return;
            }
            // Enrollment-claim TTL rotation (CAPT-ENROLL-1): re-stamp the sealed
            // record before its TTL expires so acme's bearer-less first-boot DCR
            // channel never goes stale while the captain is up (boot/spawn alone
            // only stamp at process start — after the first 10 minutes every
            // fresh DCR mint 401'd). Cheap idempotent no-op while the record is
            // fresh (captain DESIGN §7 task topology).
            crate::bootstrap::restamp_enrollment_if_expiring();
            run_tick(
                &conn,
                &config,
                &live_catalog,
                health_probe_failures,
                cooldown_reset_s,
            )
            .await;
            tokio::time::sleep(tick).await;
        }
    });
}

async fn run_tick(
    conn: &glide::GlideClient,
    config: &CaptainConfig,
    live_catalog: &Arc<RwLock<HashMap<String, crate::catalog::ServiceCatalogEntry>>>,
    health_probe_failures: u32,
    cooldown_reset_s: i64,
) {
    let instances = match store::list_for_ip(conn, &config.local_ip).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "monitor: failed to list instances");
            return;
        }
    };
    for inst in instances {
        let entry = match live_catalog.read().unwrap().get(&inst.service_type) {
            Some(e) => e.clone(),
            None => continue,
        };
        let pid = inst.pid;
        if pid == 0 {
            // pid == 0 means the instance was Killed (or BindFailed) and the pid
            // was cleared. Try to self-heal (restart) if restarts < MAX_RESTARTS
            // — but NOT during shutdown (don't fight shutdown_all_services),
            // and NOT if an upgrade is in progress for this instance (the
            // upgrade's abort path handles cleanup). BindFailed is TERMINAL
            // (captain DESIGN §8 invariant 10): the child died binding a port
            // held by a foreign process — respawning would loop against the
            // same holder, so the row is left for operator intervention.
            if inst.status == "BindFailed" {
                continue;
            }
            if inst.status == "Killed"
                && !SHUTTING_DOWN.load(Ordering::SeqCst)
                && !is_upgrade_in_progress(conn, &inst.key).await
            {
                let _ = supervisor::self_heal(conn, &inst, &entry).await;
            }
            continue;
        }
        // Process dead?
        if !procfs::pid_alive(pid) {
            if supervisor::is_intentionally_stopped(pid) || SHUTTING_DOWN.load(Ordering::SeqCst) {
                // Already being stopped by Captain (or we're shutting down)
                // — let `stop` / `shutdown_all_services` handle it.
                continue;
            }
            // Don't self-heal if an upgrade is in progress for this
            // instance — the upgrade's abort path will stop the new
            // instance and clean it up. Self-healing here would respawn
            // the crashed process and fight the upgrade.
            if is_upgrade_in_progress(conn, &inst.key).await {
                tracing::info!(
                    service = %inst.service_type,
                    key = %inst.key,
                    pid,
                    "monitor: process dead but upgrade in progress — skipping self-heal"
                );
                continue;
            }
            let _ = supervisor::self_heal(conn, &inst, &entry).await;
            continue;
        }
        // Sample CPU/memory — tick-based (diff between consecutive
        // monitor ticks, no sleep). Same 10s window as the host CPU
        // sample, so per-service and host CPU% are directly comparable.
        let sample = procfs::sample_tick(pid);

        // Startup grace period: skip health probes for instances that
        // were started less than 15 seconds ago. This gives services
        // time to bind their port and connect to the DB. Operations like
        // CA init, DCR, and M2M registration should happen AFTER the
        // health endpoint is up — they are post-startup tasks, not
        // startup-blocking tasks.
        let now = chrono::Utc::now().timestamp();
        let startup_age = inst.started_at.map(|s| now - s).unwrap_or(0);
        let in_startup_grace = startup_age < 15;
        // CAPT-PROBE-3 (DESIGN §5.10.2): the TLS WARM-UP grace (classified AFTER the probe
        // below). A fresh service binds its listener FIRST but accepts
        // handshakes only once its on-demand server cert has landed from
        // acme — until then every probe dies with `AccessDenied` (or never
        // connects). Under fleet-wide cold starts / retry storms the acme
        // mint path can stay saturated LONGER than the raw probe threshold,
        // so killing on it mass-murdered just-started installs. Within
        // `cert_grace_s`, an AccessDenied probe resets the failure counter
        // instead of counting toward the kill.
        let in_cert_grace = startup_age < config.cert_grace_s.max(0);

        // Health probe — skip for workers (no inbound port / health endpoint).
        // Also skip during startup grace period (probe always succeeds).
        let is_worker = sentin8::config::is_worker_service(&inst.service_type);
        let probe = if is_worker || in_startup_grace {
            health::HealthProbe {
                ok: procfs::pid_alive(pid),
                latency_ms: 0.0,
                handshake_ms: None,
                status_code: None,
                error: String::new(),
                version: None,
                build: None,
                active_connections: None,
            }
        } else {
            // Use health_port offset if set (e.g. proxy/tls management API
            // = local_port + 10000), otherwise use the service's local_port.
            let port = if entry.health_port > 0 {
                inst.local_port + entry.health_port
            } else {
                inst.local_port
            };
            health::probe(
                &inst.local_ip,
                port,
                crate::catalog::HEALTH_PATH,
                crate::catalog::HEALTH_TIMEOUT_MS,
                &inst.service_type,
                entry.use_http_health,
            )
            .await
        };
        // Update rolling window.
        let mut win = {
            let m = windows().lock().unwrap();
            m.get(&inst.key).cloned().unwrap_or_default()
        };
        push_sample(&mut win.cpu, sample.cpu_pct);
        push_sample(&mut win.mem, sample.mem_pct);
        push_sample(&mut win.rss_mb, sample.rss_mb);
        push_sample(&mut win.latency, probe.latency_ms);
        // CAPT-7 visibility: log the handshake/request split on cold connects
        // so an operator can tell a handshake-inflated sample (post-restart
        // / post-retry) from a warm sub-ms one in the rolling average.
        if let Some(hs_ms) = probe.handshake_ms {
            tracing::debug!(
                service = %inst.service_type,
                key = %inst.key,
                handshake_ms = hs_ms,
                total_rtt_ms = probe.latency_ms,
                "cold probe connection — PQ handshake paid (amortizing)"
            );
        }
        let cpu_avg = avg(&win.cpu);
        let mem_avg = avg(&win.mem);
        let rss_mb_avg = avg(&win.rss_mb);
        let lat_avg = avg(&win.latency);
        // Update metrics row regardless of probe result (CPU/mem are still valid).
        let _ = store::update_metrics(conn, &inst, cpu_avg, mem_avg, rss_mb_avg, lat_avg).await;
        // Capture version+build from the health endpoint (reported by each
        // service individually). Stored on the instance so `sentin8 captain
        // services` shows the actual binary version, not captain's own.
        if probe.ok && (probe.version.is_some() || probe.build.is_some()) {
            let _ = store::update_version_build(
                conn,
                &inst,
                probe.version.as_deref(),
                probe.build.as_deref(),
            )
            .await;
        }
        win.last_probe_error = probe.error.clone();
        if probe.ok {
            win.consecutive_failures = 0;
            // Starting/Started → Active on first healthy probe.
            // The health endpoint responding means the service is ready
            // for traffic — no need to wait a second tick.
            if inst.status == "Starting" || inst.status == "Started" {
                let _ = store::mark_active(conn, &inst).await;
                // WARN-10: the service recovered — clear any crash-loop
                // alert so the operator surface reflects reality.
                if let Err(e) = store::clear_alert(conn, &inst.service_type).await {
                    tracing::debug!(error = ?e, service = %inst.service_type, "alert clear failed");
                }
                win.started_ticks = 0;
            }
            if inst.status == "Active" {
                win.started_ticks += 1;
                // Cooldown reset: if healthy for > cooldown_reset_s, reset restarts.
                let healthy_for_s = win.started_ticks as i64 * config.monitor_tick_s as i64;
                if cooldown_due(healthy_for_s, cooldown_reset_s, inst.restarts) {
                    let _ = store::reset_restarts(conn, &inst).await;
                    win.started_ticks = 0;
                }
            }
        } else {
            win.consecutive_failures += 1;
            // CAPT-PROBE-3 (DESIGN §5.10.2): TLS warm-up — not unresponsiveness. The
            // process is alive (we only reach this branch past the
            // pid-alive check); its cert fetch is pending. Both warm-up
            // shapes share the window: the listener answered the TCP
            // connect and the TLS layer refused until the cert lands
            // (`AccessDenied` alert / certificate- or handshake-bearing
            // rustls text) — or the connect never comes back because the
            // resolver is still waiting for the very first cert (refusal
            // + timeout forms). Within `cert_grace_s` such failures reset
            // the counter instead of counting toward the kill; a failure
            // that PERSISTS past the grace window counts again and the
            // normal kill path proceeds (a permanent TLS misconfig
            // eventually gets killed exactly like before).
            if tls_warm_up(probe_error_signature(&probe.error)) && in_cert_grace {
                tracing::debug!(
                    service = %inst.service_type,
                    key = %inst.key,
                    startup_age_s = startup_age,
                    error = %probe.error,
                    "probe failed on TLS warm-up (cert fetch pending) — in grace, not counting"
                );
                win.consecutive_failures = 0;
            }
            // CAPT-5 (captain DESIGN §5): the monitor NEVER kills captain itself —
            // the self-probe goes through the same tokio runtime that services the
            // management API, so a busy window (an upgrade's 60s soak, a drain
            // poll burst) can starve 2s-timeout probes without the process being
            // unhealthy. Killing it would commit suicide mid-upgrade, orphaning
            // the fleet. The failure counter is tracked (visibility) but the
            // kill branch is skipped for the captain's own service type; the
            // process-level watchdog is the OS supervisor's job, not our own.
            if win.consecutive_failures >= health_probe_failures {
                if inst.service_type == "sentin8:captain" {
                    tracing::warn!(
                        service = %inst.service_type,
                        pid,
                        failures = win.consecutive_failures,
                        "captain self-probe failed — NOT killing self (monitor must never commit suicide)"
                    );
                    win.consecutive_failures = 0;
                } else {
                    // Unresponsive but alive → kill, then self-heal. The last probe's
                    // error string rides the kill log — a misdiagnosed kill (stale
                    // pooled connection, timeout vs refusal) must be auditable.
                    tracing::warn!(
                        service = %inst.service_type,
                        pid,
                        failures = win.consecutive_failures,
                        last_probe_error = %win.last_probe_error,
                        "health probes failed; killing unresponsive process"
                    );
                    let _ = unsafe { kill_signal(pid, 9) };
                    // Next tick will see it dead and self-heal.
                    win.consecutive_failures = 0;
                }
            }
        }
        {
            let mut m = windows().lock().unwrap();
            m.insert(inst.key, win);
        }
    }
    // After metrics: run the scaler (skip during shutdown).
    if !SHUTTING_DOWN.load(Ordering::SeqCst) {
        let _ = crate::scaler::evaluate(conn, config).await;
    }

    // Sample whole-host CPU/memory and store in Valkey for the Machines
    // table. One sample per tick — the CLI reads the latest value.
    // PROVISION-1 : the payload is annotated with a
    // `saturated` flag when the host crosses the saturation thresholds
    // the autoscaler role (crate::provision) reads this annotation from
    // Valkey; no cross-machine RPC, no new metric pipeline.
    let host = crate::procfs::sample_host();
    let saturated = crate::provision::is_saturated(host.cpu_pct, host.mem_pct);
    if saturated {
        // Which service is busy on this machine? The busiest Active instance
        // (highest CPU) is recorded with the annotation — the autoscaler's
        // decision needs the busy service to check it is at
        // MAX_INSTANCES before provisioning.
        let instances = crate::store::list_for_ip(conn, &config.local_ip)
            .await
            .unwrap_or_default();
        let busy_service = instances
            .iter()
            .filter(|i| i.status == "Active")
            .max_by(|a, b| {
                a.cpu_avg_1m
                    .partial_cmp(&b.cpu_avg_1m)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|i| i.service_type.clone())
            .unwrap_or_default();
        tracing::warn!(
            cpu_pct = host.cpu_pct,
            mem_pct = host.mem_pct,
            busy_service = %busy_service,
            "captain.scale.capacity: host at saturation threshold"
        );
        let host_key = format!("captain:host:{}", config.local_ip);
        let host_payload = serde_json::json!({
            "cpu_pct": host.cpu_pct,
            "mem_pct": host.mem_pct,
            "used_mb": host.used_mb,
            "ts": chrono::Utc::now().timestamp(),
            "saturated": true,
            "saturated_service": busy_service,
        });
        let _: () = glide::cmd("SET")
            .arg(&host_key)
            .arg(serde_json::to_string(&host_payload).unwrap_or_default())
            .arg("EX")
            .arg(120) // 2-minute TTL — stale if captain dies
            .query_async(conn)
            .await
            .unwrap_or(());
    } else {
        let host_key = format!("captain:host:{}", config.local_ip);
        let host_payload = serde_json::json!({
            "cpu_pct": host.cpu_pct,
            "mem_pct": host.mem_pct,
            "used_mb": host.used_mb,
            "ts": chrono::Utc::now().timestamp(),
            "saturated": false,
        });
        let _: () = glide::cmd("SET")
            .arg(&host_key)
            .arg(serde_json::to_string(&host_payload).unwrap_or_default())
            .arg("EX")
            .arg(120) // 2-minute TTL — stale if captain dies
            .query_async(conn)
            .await
            .unwrap_or(());
    }

    // Machine auto-provisioning
    // the elected leader evaluates scale-out/scale-in on every tick. The
    // profile gate inside `evaluate` makes this inert with the default
    // `never` profile. Skipped during shutdown.
    if !SHUTTING_DOWN.load(Ordering::SeqCst) {
        let _ = crate::provision::evaluate(conn, config).await;
    }

    // Fleet enrollment publication (FLEET-2, DESIGN §11.2): publish the
    // CURRENT sealed record to `captain:enrollment:{ip}` so any machine's
    // acme can verify any machine's first-boot claim (multi-host fleets:
    // acme is a fleet singleton pinned to the base machine, but a
    // provisioned machine's workloads still need enrollment mints). Same
    // 120s freshness window as the host sample — a dead machine's record
    // expires with its host row. Fail-open (best-effort write): the
    // LOCAL sealed file remains the authoritative verification path on
    // the machine that owns acme.
    if !SHUTTING_DOWN.load(Ordering::SeqCst) {
        if let Ok((secret, ts)) = crate::bootstrap::ensure_enrollment() {
            let enr_key = format!("captain:enrollment:{}", config.local_ip);
            let enr_payload = serde_json::json!({
                "secret": secret,
                "generated_at": ts,
                "ip": config.local_ip,
            });
            let _: () = glide::cmd("SET")
                .arg(&enr_key)
                .arg(serde_json::to_string(&enr_payload).unwrap_or_default())
                .arg("EX")
                .arg(120) // same freshness window as captain:host:{ip}
                .query_async(conn)
                .await
                .unwrap_or(());
        }
    }
}

fn push_sample(buf: &mut Vec<f32>, v: f32) {
    if buf.len() >= WINDOW_SIZE {
        buf.remove(0);
    }
    buf.push(v);
}

/// Cooldown decision seam — pure so TEST-1 can pin the reset policy:
/// `restarts` resets to 0 only after the instance has been healthy for at
/// least `cooldown_reset_s` AND has a positive restart count (a clean
/// instance never needs a reset).
/// Handle cooldown due.
pub fn cooldown_due(healthy_for_s: i64, cooldown_reset_s: i64, restarts: i32) -> bool {
    healthy_for_s >= cooldown_reset_s && restarts > 0
}

/// The failure signature a probe surfaces while a service's TLS layer is
/// still waiting for its on-demand server cert (CAPT-PROBE-3, DESIGN §5.10.2).
///
/// Two concrete shapes:
/// - `WarmRejected`: the listener accepted the TCP connect but the TLS
///   layer rejected/failed the handshake until the cert lands — the
///   probe error carries the `AccessDenied` alert, or certificate- /
///   handshake-bearing rustls text.
/// - `NeverConnected`: the resolver is waiting for the very FIRST cert
///   so nothing is listening behind the TLS accept yet — connect
///   refusal / timeout with no HTTP layer reached at all (no status
///   code; the probe's transport failure class).
///
/// `NonTls` is everything else (a non-2xx status IS an HTTP-layer
/// answer — an app-level failure, never warm-up).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WarmUpSignature {
    /// TLS layer rejected the handshake while waiting for a cert.
    WarmRejected,
    /// Connect-level failure before any TLS answer (resolver waiting).
    NeverConnected,
    /// Not a warm-up failure.
    NonTls,
}

/// Classify a probe failure string into the warm-up signature. Public
/// pure seam (mirrors [`cooldown_due`]) so the classification policy is
/// unit-pinned without Valkey.
pub fn probe_error_signature(error: &str) -> WarmUpSignature {
    if error.is_empty() {
        return WarmUpSignature::NonTls;
    }
    // A non-2xx status IS an HTTP-layer answer — the service is up and
    // speaking TLS but broken; a warm-up grace must NEVER mask it.
    if error.starts_with("non-2xx status") {
        return WarmUpSignature::NonTls;
    }
    if error.contains("AccessDenied")
        || error.contains("certificate")
        || error.contains("handshake")
    {
        return WarmUpSignature::WarmRejected;
    }
    // Everything else with no HTTP answer reached (connect refusal /
    // timeout text) → the resolver is waiting for the very first cert.
    WarmUpSignature::NeverConnected
}

/// Should this probe failure be forgiven as TLS warm-up (the counter
/// resets instead of counting toward the kill)?
pub fn tls_warm_up(signature: WarmUpSignature) -> bool {
    !matches!(signature, WarmUpSignature::NonTls)
}

fn avg(buf: &[f32]) -> f32 {
    if buf.is_empty() {
        0.0
    } else {
        buf.iter().sum::<f32>() / buf.len() as f32
    }
}

extern "C" {
    fn kill(pid: u32, sig: i32) -> i32;
}
unsafe fn kill_signal(pid: u32, sig: i32) -> i32 {
    kill(pid, sig)
}

/// Spawn a background task that subscribes to `stat:rollups:day` on
/// Valkey and updates both API call counts and error/warning counts on
/// service instances.
///
/// Stat's embedded worker aggregates raw metrics from services into
/// rolling 24-hour rollups published every 10s to `stat:rollups:day`:
/// `{"granularity":"day","ts":"...","metrics":[
/// {"source":"proxy","metric":"proxy.traffic.{from}→{to}.count","value":,...},
/// {"source":"self","metric":"log.errors.sentin8-auth","value":,...},
/// {"source":"self","metric":"log.warnings.sentin8-auth","value":,...}
/// ]}`
///
/// The subscriber processes both metric types:
/// - `proxy.traffic.{from}→{to}.count` → sums per `to` service → overwrites `api_calls`
/// - `log.errors.{service}` / `log.warnings.{service}` → overwrites `errors`/`warnings`
///
/// Both are authoritative 24-hour aggregates from Stat's embedded worker, so
/// captain overwrites (not accumulates) the values.
fn spawn_rollup_metrics_subscriber(
    conn: glide::GlideClient,
    config: CaptainConfig,
    live_catalog: Arc<RwLock<HashMap<String, crate::catalog::ServiceCatalogEntry>>>,
) {
    let valkey_url = config.valkey_url.clone();
    let local_ip = config.local_ip.clone();
    tokio::spawn(async move {
        let client = match sentin8::middleware::valkey_client_pubsub(&valkey_url, "sentin8:captain")
            .await
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "monitor: failed to open Valkey client for rollup metrics");
                return;
            }
        };
        loop {
            use glide::PubSubCommands as _;
            if let Err(e) = client.subscribe(&["stat:rollups:day"]).await {
                tracing::warn!(error = %e, "monitor: subscribe to stat:rollups:day failed");
                tokio::time::sleep(Duration::from_secs(3)).await;
                continue;
            }
            tracing::info!(
                "monitor: subscribed to stat:rollups:day for API call + error/warning counts"
            );
            loop {
                let msg = client.get_pubsub_message().await;
                let payload: String = match msg {
                    Ok(m) => String::from_utf8_lossy(&m.payload).into_owned(),
                    Err(_) => {
                        tracing::warn!("monitor: stat:rollups:day channel ended; reconnecting");
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        break;
                    }
                };
                let parsed: serde_json::Value = match serde_json::from_str(&payload) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                // Rollup payload: {"metrics": [ {metric, value, ...}, ... ]}
                let metrics = match parsed.get("metrics").and_then(|m| m.as_array()) {
                    Some(a) => a,
                    None => continue,
                };

                // Accumulate per service: (api_calls, errors, warnings).
                let mut service_counts: HashMap<String, (i64, i64, i64)> = HashMap::new();
                for item in metrics {
                    let name = match item.get("metric").and_then(|m| m.as_str()) {
                        Some(s) => s,
                        None => continue,
                    };
                    let value = item.get("value").and_then(|v| v.as_f64()).unwrap_or(0.0) as i64;

                    // 1. Traffic metrics: proxy.traffic.{from}→{to}.count
                    if name.ends_with(".count") {
                        if let Some(rest) = name.strip_prefix("proxy.traffic.") {
                            if let Some(pair_end) = rest.find(".count") {
                                let pair_str = &rest[..pair_end];
                                if let Some(arrow_pos) = pair_str.find('→') {
                                    let to_service = &pair_str[arrow_pos + 3..]; // skip `→` (3 bytes)
                                    let entry = service_counts
                                        .entry(to_service.to_string())
                                        .or_insert((0, 0, 0));
                                    entry.0 += value;
                                }
                            }
                        }
                    }

                    // 2. Error/warning metrics: log.errors.{service} / log.warnings.{service}
                    if let Some(rest) = name.strip_prefix("log.errors.") {
                        let entry = service_counts.entry(rest.to_string()).or_insert((0, 0, 0));
                        entry.1 = value;
                    } else if let Some(rest) = name.strip_prefix("log.warnings.") {
                        if rest != "total" {
                            let entry = service_counts.entry(rest.to_string()).or_insert((0, 0, 0));
                            entry.2 = value;
                        }
                    }
                }

                // Update each service instance in Valkey.
                let conn = conn.clone();
                for (service_name, (api_calls, errors, warnings)) in &service_counts {
                    if live_catalog.read().unwrap().contains_key(service_name) {
                        if *api_calls > 0 {
                            let _ =
                                store::set_api_calls(&conn, &local_ip, service_name, *api_calls)
                                    .await;
                        }
                        // Error/warning counts from Stat's rollups are
                        // **snapshots** (rolling 24-hour aggregates), not
                        // deltas. Overwrite the stored value instead of
                        // accumulating — otherwise the count climbs every
                        // 10s when stat republishes the same rollup.
                        if *errors > 0 || *warnings > 0 {
                            let _ = store::set_error_warning_counts(
                                &conn,
                                &local_ip,
                                service_name,
                                *errors,
                                *warnings,
                            )
                            .await;
                        }
                    }
                }
            }
            tracing::warn!("monitor: rollup metrics Valkey stream ended; reconnecting in 3s");
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    });
}

/// Spawn a background task that resets the per-day display counters
/// (`restarts`, `errors`, `warnings`) once per day at 00:00 UTC. This
/// makes the `RST`/`ERR`/`WRN` columns in `make status` show a rolling
/// 24-hour window instead of lifetime totals. `api_calls` is not reset
/// here — it is overwritten every 10s from Stat's
/// `stat:rollups:day` channel, which already provides a true 24-hour
/// aggregate.
///
/// On startup it waits until the next midnight UTC, then resets every 24h.
/// If the wait until midnight would exceed 25h (clock skew / edge case) it
/// falls back to an immediate reset + 24h interval.
fn spawn_daily_reset(conn: glide::GlideClient, config: CaptainConfig) {
    let local_ip = config.local_ip.clone();
    tokio::spawn(async move {
        loop {
            // Sleep until the next 00:00 UTC.
            let now = chrono::Utc::now();
            let next = (now + chrono::Duration::days(1))
                .date_naive()
                .and_hms_opt(0, 0, 0)
                .unwrap();
            let until_midnight = next
                .signed_duration_since(now.naive_utc())
                .to_std()
                .unwrap_or(Duration::from_secs(0));
            let until_midnight = if until_midnight > Duration::from_secs(25 * 3600) {
                tracing::warn!("monitor: time until midnight >25h; resetting now");
                Duration::from_secs(0)
            } else {
                until_midnight
            };
            tokio::time::sleep(until_midnight).await;

            let conn = conn.clone();
            match store::reset_daily_counters(&conn, &local_ip).await {
                Ok(n) if n > 0 => {
                    tracing::info!(
                        reset = n,
                        "monitor: daily counter reset (RST/ERR/WRN/CALLS → 0)"
                    );
                }
                Ok(_) => {} // nothing to reset
                Err(e) => {
                    tracing::warn!(error = ?e, "monitor: daily counter reset failed");
                }
            }
            // Guard against a tight loop if the clock jumps backward.
            tokio::time::sleep(Duration::from_secs(60)).await;
        }
    });
}

/// CAPT-ALERT-2 (captain DESIGN §5.10.1): last-resort respawn ticker.
///
/// A service that exhausted MAX_RESTARTS parks with an alert. An operator
/// away during the failure used to find the fleet permanently down until
/// someone read the alert. This task re-attempts ONE spawn for every
/// alerted service every `last_resort_respawn_s` seconds (alert stays
/// raised until the service reaches Active, which clears it through the
/// regular monitor path). 0 disables. The respawn rides the same
/// supervisor spawn path as any start (fresh registry row at a fresh
/// port) — never a manual process launch.
fn spawn_last_resort_respawner(
    conn: glide::GlideClient,
    config: CaptainConfig,
    live_catalog: Arc<RwLock<HashMap<String, crate::catalog::ServiceCatalogEntry>>>,
) {
    if config.last_resort_respawn_s <= 0 {
        return;
    }
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(config.last_resort_respawn_s as u64)).await;
            if SHUTTING_DOWN.load(Ordering::SeqCst) {
                return;
            }
            let c = conn.clone();
            let Ok(alerts) = store::list_alerts(&c).await else {
                continue;
            };
            for (_svc, alert) in alerts {
                // Already running? (a previous respawn succeeded but the
                // alert was never cleared, or another instance exists.)
                let existing = store::list_all(&c)
                    .await
                    .map(|v| {
                        v.iter().any(|i| {
                            i.service_type == alert.service_type
                                && i.status != "Stopped"
                                && i.status != "Killed"
                        })
                    })
                    .unwrap_or(false);
                if existing {
                    continue;
                }
                let Some(entry) = live_catalog
                    .read()
                    .unwrap()
                    .get(&alert.service_type)
                    .cloned()
                else {
                    continue;
                };
                tracing::warn!(
                    service = %alert.service_type,
                    interval_s = config.last_resort_respawn_s,
                    "captain: last-resort respawn attempt for an alerted service"
                );
                if let Err(e) = crate::handlers::spawn_one_service(
                    &c,
                    &config.local_ip,
                    config.port_range,
                    &alert.service_type,
                    &entry,
                )
                .await
                {
                    tracing::error!(error = %e, service = %alert.service_type, "last-resort respawn failed");
                }
            }
        }
    });
}
