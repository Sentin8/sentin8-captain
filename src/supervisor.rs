// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Process supervisor - spawn / stop / adopt / self-heal.
//!
//! Owns the in-memory set of intentionally-stopped pids (to distinguish
//! `Stopped` from `Killed`), the restart backoff schedule, the
//! drain-until-idle helper (poll the instance's health gauge,
//! cap-bounded - captain README §7), and the Post alert INSERT.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use crate::catalog::ServiceCatalogEntry;
use crate::store;

/// Max consecutive restarts before Captain stops retrying and alerts.
/// The max restarts constant.
pub const MAX_RESTARTS: i32 = 3;

/// Upper bound on the drain-until-idle wait ([`drain_until_idle`]) -
/// upgrades must never block indefinitely on a wedged connection
/// (captain README §7).
pub const DRAIN_CAP_S: u64 = 30;

/// Drain an instance by polling its `active_connections` health gauge
/// (captain README §7, drain contract shared with proxy README §7).
///
/// `gauge` reads the instance's in-flight connection count. Semantics:
///
/// - gauge reported and 0 → drain complete (exit immediately).
/// - gauge reported and > 0 → poll again every 500ms, capped at `cap_s`
///   total (the 30s ceiling - upgrades must never block indefinitely).
/// - gauge unavailable (health probe failed, or the payload has no
///   `active_connections` - a non-gauge service) → fall back to sleeping
///   the fixed `fallback_s` window (the pre-gauge behavior, bounded by
///   `cap_s`).
///
/// Returns the elapsed drain duration (for logging). `cap_s` and
/// `fallback_s` are parameters so tests can use tiny windows; production
/// passes [`DRAIN_CAP_S`] and the configured `upgrade_drain_s`.
pub async fn drain_until_idle<F, G>(mut gauge: F, cap_s: u64, fallback_s: u64) -> Duration
where
    F: FnMut() -> G,
    G: std::future::Future<Output = (Option<u64>, bool)> + Send,
{
    let started = tokio::time::Instant::now();
    let cap = Duration::from_secs(cap_s);
    let fallback = Duration::from_secs(fallback_s).min(cap);
    loop {
        let (count, probe_failed) = gauge().await;
        match (count, probe_failed) {
            // Gauge unavailable (probe failed, or the payload has no
            // `active_connections` - a non-gauge service): fall back to
            // the fixed drain window so upgrades still bound.
            (_, true) | (None, false) => {
                tokio::time::sleep(fallback.saturating_sub(started.elapsed())).await;
                break;
            }
            // Drain complete - in-flight connections reached zero.
            (Some(0), false) => break,
            // Still draining - poll again in 500ms (or hit the cap).
            (Some(_), false) => {
                if started.elapsed() >= cap {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    started.elapsed()
}

/// Register a child so it gets reaped when it exits. Spawns a background
/// task that calls `wait` so the OS can clean up the zombie, plus a
/// bind-failure classifier: a child that dies within seconds of spawn
/// having never served traffic is checked for the classic bind-failure
/// signature (`failed to bind ... Address already in use`) in its log -
/// the respawn is FUTILE (the port is held by a foreign process) and must
/// NOT be retried (captain DESIGN §8 invariant 10). The row is marked
/// `BindFailed` and deleted, and the alert fires; the monitor's kill/respawn
/// path never sees it. The child handle is owned by the task (not stored in
/// a map) - we only track the pid for cleanup lookups.
pub fn register_child(pid: u32, child: tokio::process::Child) {
    tokio::spawn(async move {
        let mut child = child;
        let _ = child.wait().await;
        // The process has exited. Classify the exit for the futile-respawn guard:
        // a fast-failing child that died binding its port is terminal.
        reap_and_classify(pid).await;
    });
}

/// Grace window after spawn inside which a fresh child's death is still
/// "startup failure" rather than a later runtime crash. Bind failures
/// surface within the first couple of seconds (the bind is the first
/// bind() after config load); anything longer than this window is left
/// to the monitor's normal kill/respawn path.
pub const STARTUP_FAIL_WINDOW_S: u64 = 10;

/// Classify a freshly-exited child (captain DESIGN §8 invariant 10):
/// find the exited child's registry row (alive only while `[`STARTUP_FAIL_WINDOW_S`]`
/// of spawn - enforced by the `started_at` check below since `row_for_pid`
/// only sees rows the reaping has not yet deleted) AND check its service log
/// (the spawn redirects stderr there) for the bind-failure signature; on a
/// match mark the row `BindFailed` (pid 0) and DELETE it - the port is held
/// by a foreign process, so respawning against it is futile and must never
/// be retried; the alert (`captain.service.bind_failed`) surfaces the
/// terminal state. A child that bound fine and crashed later does not carry
/// the signature in a fresh log tail and stays on the monitor's normal
/// kill/respawn path.
async fn reap_and_classify(pid: u32) {
    tokio::time::sleep(Duration::from_millis(100)).await;
    let Some((ip, port, service, started_at)) = row_for_pid(pid).await else {
        return; // row already deleted (upgrade cleanup, stop, …)
    };
    // Freshness gate: only a child that exited within the startup window is
    // classified - a long-lived process dying while the log still contains an
    // OLD bind failure must never be misread (log files are append-only).
    let now = chrono::Utc::now().timestamp();
    if started_at.is_none_or(|t| now - t > STARTUP_FAIL_WINDOW_S as i64) {
        return;
    }
    let log_path = std::path::Path::new(&sentin8::config::log_dir()).join(format!("{service}.log"));
    let Some(tail) = tail_file(&log_path, 8_000) else {
        return;
    };
    if !tail.contains("failed to bind") || !tail.contains("Address already in use") {
        return; // not a bind failure - normal reaping
    }
    let Some(conn) = registry_conn().await else {
        return;
    };
    if let Ok(all) = store::list_all(&conn).await {
        if let Some(inst) = all.iter().find(|i| i.pid == pid) {
            let mut dead = inst.clone();
            dead.status = "BindFailed".into();
            dead.pid = 0;
            dead.last_health_check = Some(chrono::Utc::now().timestamp());
            // Upsert the terminal row (publishes captain:changed) then delete it
            // - the delete frees the port for the registry; the status mark keeps
            // pub/sub consumers from serving the dead pid in the interim.
            let _ = store::upsert_instance(&conn, &dead).await;
            let _ = store::delete_instance(&conn, &dead).await;
        }
    }
    tracing::error!(
        service = %service,
        ip = %ip,
        port,
        pid,
        "captain.service.bind_failed: child died binding its port - the port is held by another process; the instance is NOT respawned (respawning would loop against the same holder)"
    );
}

/// A standalone registry connection for the reaper task (the supervisor has
/// no shared pool; the monitor's glide::GlideClient is not reachable here).
/// Opens its own Valkey connection - one per classified child-exit, and
/// only when the bind-failure signature matched.
async fn registry_conn() -> Option<glide::GlideClient> {
    let url = std::env::var("SENTIN8_CAPTAIN_VALKEY_URL")
        .ok()
        .or_else(|| std::env::var("VALKEY_URL").ok())
        .or_else(|| Some(sentin8::config::Sentin8Config::default_valkey_url().to_string()))?;
    sentin8::middleware::valkey_client(&url, "sentin8:captain")
        .await
        .ok()
}

/// Look up the registry row a pid belongs to, as
/// `(local_ip, local_port, service_type, started_at)`.
async fn row_for_pid(pid: u32) -> Option<(String, u16, String, Option<i64>)> {
    let conn = registry_conn().await?;
    let all = store::list_all(&conn).await.ok()?;
    all.into_iter().find(|i| i.pid == pid).map(|i| {
        (
            i.local_ip.clone(),
            i.local_port,
            i.service_type.clone(),
            i.started_at,
        )
    })
}

/// Read at most the last `max` bytes of a file (small, bounded read).
fn tail_file(path: &std::path::Path, max: usize) -> Option<String> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let start = len.saturating_sub(max as u64);
    f.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::with_capacity((len - start) as usize);
    f.read_to_end(&mut buf).ok()?;
    Some(String::from_utf8_lossy(&buf).to_string())
}

/// Exponential backoff (seconds) for restart attempts: 1, 2, 4, 8, …
/// Handle backoff delay secs.
pub fn backoff_delay_secs(restart_count: i32) -> u64 {
    1u64.checked_shl(restart_count.max(0) as u32).unwrap_or(16)
}

/// In-memory record of intentionally-stopped pids. A process whose pid is
/// in this set exited because Captain asked it to (graceful shutdown /
/// scale-down) → it is `Stopped`, not `Killed`, and does NOT increment
/// `restarts`.
fn intentionally_stopped() -> &'static Mutex<HashSet<u32>> {
    static SET: OnceLock<Mutex<HashSet<u32>>> = OnceLock::new();
    SET.get_or_init(|| Mutex::new(HashSet::new()))
}

/// Handle mark intentionally stopped.
pub fn mark_intentionally_stopped(pid: u32) {
    let _ = intentionally_stopped().lock().map(|mut s| s.insert(pid));
}

/// Handle is intentionally stopped.
pub fn is_intentionally_stopped(pid: u32) -> bool {
    intentionally_stopped()
        .lock()
        .map(|s| s.contains(&pid))
        .unwrap_or(false)
}

/// Handle forget intentionally stopped.
pub fn forget_intentionally_stopped(pid: u32) {
    let _ = intentionally_stopped().lock().map(|mut s| s.remove(&pid));
}

/// Spawn an instance. Returns the spawned pid on success.
/// This version writes to Valkey (marks the instance `Starting`). Use
/// `spawn_no_db` when the store is not yet available (bootstrap).
///
/// `carried_restarts` governs the new row's `restarts` counter: when the
/// caller respawns the SAME instance key (self-heal, restart action) it
/// passes `Some(inst.restarts)` so the consecutive-restart count survives
/// the swap - seeding 0 here would pin the counter below `MAX_RESTARTS`
/// forever and a crash-loop could never reach the give-up alert (captain
/// DESIGN §8 invariant 10). A genuinely fresh instance (scale-up, upgrade
/// to a new port) passes `None` → 0.
/// Spawn it.
pub async fn spawn(
    conn: &glide::GlideClient,
    inst: &store::ServiceInstance,
    entry: &ServiceCatalogEntry,
    local_port: u16,
    carried_restarts: Option<i32>,
) -> Result<u32, anyhow::Error> {
    let mut cmd = entry.spawn_command(local_port);
    let child = cmd.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow::anyhow!("spawned child has no pid"))?;
    // Register the child so tokio reaps it when it exits (no zombies).
    register_child(pid, child);
    // Create a NEW instance record for the new port (don't overwrite the old one).
    // The key is `{service_type}/{ip}:{port}` - so a different port = a different
    // hash field.
    let new_inst = store::ServiceInstance {
        key: store::ServiceInstance::make_key(&inst.service_type, &inst.local_ip, local_port),
        service_type: inst.service_type.clone(),
        local_ip: inst.local_ip.clone(),
        local_port,
        pid,
        start_priority: inst.start_priority,
        cpu_avg_1m: 0.0,
        memory_avg_1m: 0.0,
        rss_mb_avg_1m: 0.0,
        latency_avg_1m_ms: 0.0,
        last_health_check: None,
        status: "Starting".into(),
        restarts: carried_restarts.unwrap_or(0),
        started_at: Some(chrono::Utc::now().timestamp()),
        // CAPTAIN-10: seed EMPTY version/build - the values are UNKNOWN until
        // the first health probe captures them from the service itself.
        // Seeding captain's own `{version}.{build_hash}` pair here made
        // `make status` display a duplicated version (`.`) during
        // the startup grace period (health probes are skipped for <15s and
        // the payload carried no `build` key to overwrite the stale hash).
        // Both health sides now emit `build` (CAPTAIN-10) and the seed stays
        // empty - the VERSION column is blank, never wrong.
        version: String::new(),
        build_hash: String::new(),
        errors: 0,
        warnings: 0,
        api_calls: 0,
    };
    store::upsert_instance(conn, &new_inst).await?;
    tracing::info!(service = %entry.service_type, %local_port, pid, "spawned instance");
    Ok(pid)
}

/// Spawn an instance WITHOUT touching the DB. Used at startup when all
/// services are launched before DB access is available. The caller is
/// responsible for recording the pid/port in `orch_services` later
/// (via `reconcile_spawned`).
/// Spawn no DB.
pub async fn spawn_no_db(
    _service_type: &str,
    entry: &ServiceCatalogEntry,
    local_port: u16,
) -> Result<u32, anyhow::Error> {
    let mut cmd = entry.spawn_command(local_port);
    let child = cmd.spawn()?;
    let pid = child
        .id()
        .ok_or_else(|| anyhow::anyhow!("spawned child has no pid"))?;
    register_child(pid, child);
    Ok(pid)
}

/// Gracefully stop an instance: Inactive (drain) → wait → Stopping → SIGTERM → wait → SIGKILL.
///
/// The drain phase sets the instance to `Inactive` so TLS/Proxy stop
/// sending new traffic, then polls the instance's `active_connections`
/// health gauge (captain README §7): the drain ends as soon as the gauge hits 0,
/// bounded by the 30s cap (falling back to the fixed `drain_s` window
/// when the service exposes no gauge). The probe mirrors the monitor's
/// health probe - same `health_port` offset + HTTP flag - so it hits
/// the same endpoint the monitor already validates. The process then
/// receives SIGTERM and the instance transitions to `Stopping`.
/// Handle stop.
pub async fn stop(
    conn: &glide::GlideClient,
    inst: &store::ServiceInstance,
    entry: &ServiceCatalogEntry,
    pid: u32,
    grace_period_s: u64,
    drain_s: u64,
) -> Result<(), anyhow::Error> {
    // : Drain - set Inactive so TLS/Proxy stop sending new traffic.
    store::mark_inactive(conn, inst).await?;
    tracing::info!(
        service = %inst.service_type,
        pid,
        drain_s,
        "instance set to Inactive - draining traffic"
    );
    // drain_s = 0 (abort cleanup of an instance that never served
    // traffic) skips the drain poll entirely - the pre-gauge behavior.
    if drain_s > 0 {
        let drained = drain_until_idle(
            || {
                probe_active_connections(
                    &inst.local_ip,
                    inst.local_port,
                    entry.health_port,
                    entry.use_http_health,
                    &inst.service_type,
                )
            },
            DRAIN_CAP_S,
            drain_s,
        )
        .await;
        tracing::info!(
            service = %inst.service_type,
            pid,
            drained_ms = drained.as_millis() as u64,
            "drain finished (gauge-idle or cap)"
        );
    }

    // : Stopping - send SIGTERM.
    store::mark_stopping(conn, inst).await?;
    mark_intentionally_stopped(pid);
    let _ = unsafe { kill_signal(pid, 15) };
    // Wait for the process to exit, polling every 500ms up to grace_period_s.
    let mut waited_ms = 0u64;
    while waited_ms < grace_period_s * 1000 {
        if !crate::procfs::pid_alive(pid) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        waited_ms += 500;
    }
    // SIGKILL if still alive.
    if crate::procfs::pid_alive(pid) {
        tracing::warn!(
            pid,
            "process did not exit within grace period; sending SIGKILL"
        );
        let _ = unsafe { kill_signal(pid, 9) };
    }
    store::mark_stopped(conn, inst).await?;
    forget_intentionally_stopped(pid);
    // Remove the instance from Valkey so its port is freed for reuse and
    // `sentin8 captain services` no longer shows the stale entry.
    let _ = store::delete_instance(conn, inst).await;
    Ok(())
}

/// Self-heal: called by the monitor loop when a process is dead or
/// unresponsive. Returns the action taken.
/// The healaction type.
pub enum HealAction {
    /// Restarted the instance (pid is the new pid).
    Restarted {
        /// The new pid after restart.
        #[allow(dead_code)]
        pid: u32,
        /// Total restart count for the instance.
        #[allow(dead_code)]
        restarts: i32,
        /// Backoff seconds applied before the restart.
        #[allow(dead_code)]
        backoff_s: u64,
    },
    /// Gave up after MAX_RESTARTS; alerted via Post.
    Alerted {
        /// Total restart attempts before giving up.
        #[allow(dead_code)]
        restarts: i32,
    },
    /// Intentional stop - no action.
    NoAction,
}

/// Handle self heal.
pub async fn self_heal(
    conn: &glide::GlideClient,
    instance: &store::ServiceInstance,
    entry: &ServiceCatalogEntry,
) -> Result<HealAction, anyhow::Error> {
    let pid = instance.pid;
    // If pid is 0, the instance was already marked Killed by a previous
    // tick (mark_killed sets pid=0). We still need to restart it if
    // restarts < MAX_RESTARTS. Skip the intentionally-stopped check and
    // pid_alive check since the process is already gone.
    //
    // The counter used for BOTH the MAX gate and the respawn carry is the
    // FRESH post-increment value from `mark_killed` - carrying the
    // monitor's pre-increment snapshot re-seeded 0 on every cycle, the
    // count never grew, `MAX_RESTARTS` was unreachable, and boot-panic
    // crash-loops ran for hours (captain DESIGN §8 invariant 10).
    let killed = if pid != 0 {
        if is_intentionally_stopped(pid) {
            return Ok(HealAction::NoAction);
        }
        // Mark killed and increment restarts.
        store::mark_killed(conn, instance).await?
    } else {
        // pid == 0: already marked Killed (counter already carried).
        instance.clone()
    };
    if killed.restarts >= MAX_RESTARTS {
        // WARN-10: the give-up is a FIRST-CLASS operator event, not a log
        // line - record a captain:alerts entry (the startup stream + CLI
        // surface it) alongside the error log.
        let log_path = format!(
            "{}/logs/{}.log",
            sentin8::config::run_dir(),
            instance.service_type.replace(':', "_")
        );
        let alert = store::ServiceAlert {
            service_type: instance.service_type.clone(),
            restarts: killed.restarts,
            reason: format!(
                "crash loop: {n} restarts without reaching Active - check the service log for the boot error",
                n = killed.restarts
            ),
            log_path,
            at: chrono::Utc::now().timestamp(),
        };
        if let Err(e) = store::record_alert(conn, &alert).await {
            tracing::warn!(error = ?e, service = %instance.service_type, "failed to record the give-up alert");
        }
        alert_service_failed(&instance.service_type, killed.restarts);
        // DUPROW-1 (DESIGN §5.10.2, "check the live process, not just the
        // row"): a live SIBLING row of the same service absorbs the
        // alert's recovery duty - the service is NOT down, and deleting
        // this row while the sibling serves must not leave the alert
        // driving the last-resort respawner into minting a duplicate.
        let siblings = store::list_for_ip(conn, &instance.local_ip)
            .await
            .unwrap_or_default();
        let live_sibling = siblings.iter().any(|s| {
            s.key != instance.key && s.service_type == instance.service_type && s.pid != 0
        });
        // Remove the dead instance so its port can be reused.
        let _ = store::delete_instance(conn, instance).await;
        if live_sibling {
            tracing::info!(
                service = %instance.service_type,
                "give-up: a live sibling instance serves this type - alert stays raised, no duplicate respawn duty"
            );
        }
        return Ok(HealAction::Alerted {
            restarts: killed.restarts,
        });
    }
    let backoff_s = backoff_delay_secs(killed.restarts);
    if backoff_s > 0 {
        tokio::time::sleep(Duration::from_secs(backoff_s)).await;
    }
    // DUPROW-1 (DESIGN §5.10.2, "check the live process, not just the
    // row"): a SECOND dead row of the same service must not mint a
    // duplicate process when a live SIBLING row already serves the
    // type. Two concurrently-dead rows (the pre-existing doubles; a
    // kill-loop cycling both) would otherwise EACH self-heal, minting
    // two fresh processes per cycle forever. The sibling absorbs the
    // service; THIS row is deleted (the duplicate is worse than the
    // lost row - the sibling's monitor path keeps the service alive).
    let siblings = store::list_for_ip(conn, &killed.local_ip)
        .await
        .unwrap_or_default();
    let live_sibling = siblings.iter().any(|s| {
        s.key != killed.key && s.service_type == killed.service_type && s.pid != 0
    });
    if live_sibling {
        tracing::warn!(
            service = %killed.service_type,
            key = %killed.key,
            "self-heal: a live sibling instance serves this type - deleting the dead duplicate row instead of respawning"
        );
        let _ = store::delete_instance(conn, &killed).await;
        return Ok(HealAction::NoAction);
    }
    // ORPHANLOOP-1 (DESIGN §5.10.2b, seam 2 - "the port is the truth; the
    // row is a cache"): before any same-key respawn, check whether a LIVE
    // process already holds the target port. A stop/start can leave a
    // healthy orphan serving with NO registry row (its boot spawn died at
    // bind against this very process - that is WHY the row is stale); a
    // blind respawn here minted a child that died binding, wrote no row,
    // and the 25s kill-respawn loop repeated forever. Adopt-or-abstain:
    let expected_binary = crate::server::expected_binary_for(&killed.service_type, Some(entry));
    if let Some(holder_pid) = crate::server::pid_on_port(killed.local_port) {
        if crate::server::is_expected_binary(holder_pid, &expected_binary) {
            // The row-less live process IS this service - adopt it: the row
            // is re-created at its live pid (status Active, alert cleared)
            // and NO child is spawned. The next probe succeeds and the
            // split-brain converges on this first heal cycle.
            let mut adopted = killed.clone();
            adopted.pid = holder_pid;
            adopted.status = "Active".to_string();
            adopted.last_health_check = Some(chrono::Utc::now().timestamp());
            if let Err(e) = store::upsert_instance(conn, &adopted).await {
                tracing::warn!(
                    error = %e,
                    service = %killed.service_type,
                    "self-heal: port-holder adoption upsert failed - falling through to spawn"
                );
            } else {
                let _ = store::clear_alert(conn, &killed.service_type).await;
                tracing::warn!(
                    service = %killed.service_type,
                    port = killed.local_port,
                    pid = holder_pid,
                    "self-heal: adopted the row-less live process holding the port - no duplicate spawned (ORPHANLOOP-1)"
                );
                return Ok(HealAction::NoAction);
            }
        } else {
            // A FOREIGN binary holds the port - the BindFailed posture:
            // spawn would loop against the same holder. Leave the row
            // Killed and surface the conflict for the operator.
            tracing::error!(
                service = %killed.service_type,
                port = killed.local_port,
                pid = holder_pid,
                expected_binary = %expected_binary,
                "self-heal: port held by a foreign process - row left Killed (operator intervention; respawning would loop)"
            );
            let _ = store::delete_instance(conn, &killed).await;
            return Ok(HealAction::NoAction);
        }
    }
    // Same-key respawn: carry the consecutive-restart count into the new row
    // (captain DESIGN §8 invariant 10 - a per-spawn zero pinned the counter
    // below `MAX_RESTARTS` forever, so crash-loops never reached the give-up
    // alert).
    let new_pid = spawn(
        conn,
        &killed,
        entry,
        killed.local_port,
        Some(killed.restarts),
    )
    .await?;
    Ok(HealAction::Restarted {
        pid: new_pid,
        restarts: killed.restarts,
        backoff_s,
    })
}

/// Log that a service failed to start after MAX_RESTARTS.
///
/// (Previously this INSERTed into `inbox`; the orch_services
/// registry is now Valkey-backed, so there is no DB pool available here.
/// We emit a structured `tracing::error!` instead - the Log relay picks
/// it up from the log sink.)
/// Handle alert service failed.
pub fn alert_service_failed(service_type: &str, restart_count: i32) {
    tracing::error!(
        service = service_type,
        restart_count,
        "captain.service.failed: gave up after max restarts - manual intervention may be required"
    );
}

/// Log that scale-up is blocked by machine CPU/memory caps.
///
/// (Previously this INSERTed into `inbox`; the registry is now
/// Valkey-backed with no DB pool. We emit a structured `tracing::warn!`
/// instead.)
/// Handle alert capacity.
pub fn alert_capacity(service_type: &str) {
    tracing::warn!(
        service = service_type,
        "captain.scale.capacity: scale-up blocked - machine CPU/memory at capacity cap"
    );
}

extern "C" {
    fn kill(pid: u32, sig: i32) -> i32;
}
/// Send a POSIX signal to a pid. SAFETY: caller must ensure `pid` refers to
/// a process owned by this Captain.
unsafe fn kill_signal(pid: u32, sig: i32) -> i32 {
    kill(pid, sig)
}

/// Probe one instance's health endpoint and extract the
/// `active_connections` gauge (captain README §7).
///
/// Mirrors the monitor's probe targeting (`health_port` mgmt offset,
/// `use_http_health` plain-HTTP flag) so the drain reads the same
/// endpoint the monitor probes. Returns `(Some(count), false)` when the
/// payload carries the gauge, `(None, false)` when the payload has no
/// gauge (non-gauge service - e.g. `with_own_health` services that
/// never adopted the field), and `(_, true)` when the health probe
/// itself failed (connection refused mid-shutdown is normal). Reuses
/// [`crate::health::probe`] so the warm client cache applies; the
/// short 2s timeout keeps a hung health endpoint from stretching the
/// 500ms poll loop beyond the cap.
async fn probe_active_connections(
    local_ip: &str,
    local_port: u16,
    health_port: u16,
    use_http: bool,
    service_type: &str,
) -> (Option<u64>, bool) {
    let port = if health_port > 0 {
        local_port + health_port
    } else {
        local_port
    };
    let probe = crate::health::probe(
        local_ip,
        port,
        crate::catalog::HEALTH_PATH,
        2_000,
        service_type,
        use_http,
    )
    .await;
    if !probe.ok {
        return (None, true);
    }
    (probe.active_connections, false)
}

#[cfg(test)]
mod drain_tests {
    use super::*;

    /// The gauge fn contract the helper relies on: returns
    /// `(Some(count), false)` when the health payload carries
    /// `active_connections`, `(None, false)` when it does not (non-gauge
    /// service), and `(_, true)` when the health probe failed.

    #[tokio::test]
    async fn drain_exits_when_gauge_reaches_zero() {
        // Gauge starts at 2, drops to 0 on the second poll - the drain
        // must end well before the cap instead of sleeping it fully.
        let mut reads = 0u32;
        let elapsed = drain_until_idle(
            || {
                reads += 1;
                let count = if reads >= 2 { 0 } else { 2 };
                async move { (Some(count), false) }
            },
            5,
            5,
        )
        .await;
        assert_eq!(reads, 2, "drain must stop polling once the gauge hits 0");
        assert!(elapsed < Duration::from_secs(4), "exited early, not at cap");
    }

    #[tokio::test]
    async fn drain_caps_when_gauge_never_zero() {
        // A wedged gauge (always > 0) must not block the upgrade past the
        // cap - with a 1s cap the helper returns at ~1s, not 30s.
        let elapsed = drain_until_idle(|| async { (Some(7u64), false) }, 1, 10).await;
        assert!(
            elapsed >= Duration::from_millis(500),
            "polled at least once"
        );
        assert!(elapsed < Duration::from_secs(10), "capped, not hung");
    }

    #[tokio::test]
    async fn drain_falls_back_to_fixed_window_when_gauge_absent() {
        // Non-gauge services (no `active_connections` in the payload) fall
        // back to the fixed drain window - the pre-gauge behavior - and
        // do NOT wait the full 30s cap.
        let elapsed = drain_until_idle(|| async { (None, false) }, 5, 1).await;
        assert!(
            elapsed >= Duration::from_millis(900),
            "absent gauge → full fixed window"
        );
        assert!(
            elapsed < Duration::from_secs(4),
            "fallback window, not the cap"
        );
    }

    #[tokio::test]
    async fn drain_falls_back_when_probe_fails() {
        // Health probe errors (service mid-shutdown) also degrade to the
        // fixed window instead of exiting early on a stale zero.
        let elapsed = drain_until_idle(|| async { (Some(0u64), true) }, 5, 1).await;
        assert!(
            elapsed >= Duration::from_millis(900),
            "probe failure → full fixed window (no false drain-complete)"
        );
    }

    #[tokio::test]
    async fn drain_fallback_is_bounded_by_cap() {
        // An operator-configured fallback larger than the cap is clamped -
        // the 30s ceiling holds regardless of configuration.
        let elapsed = drain_until_idle(|| async { (None, false) }, 1, 60).await;
        assert!(
            elapsed < Duration::from_secs(5),
            "fallback must be capped, never the configured 60s"
        );
    }
}
