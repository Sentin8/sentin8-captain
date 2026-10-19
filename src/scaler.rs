// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Auto-scaler - scale-up and scale-down. Runs on every monitor tick.
//!
//! **Scale-up**: a service type is busy if ALL its `Active` instances have
//! been over the busy thresholds continuously for > `BUSY_WINDOW_S`. If the
//! machine has capacity and the instance count < `MAX_INSTANCES`, spawn
//! one new instance. Max one new instance per service type per tick.
//!
//! **Scale-down**: an instance is idle if under both idle thresholds
//! continuously for > `IDLE_WINDOW_S`. If the instance count >
//! `MIN_INSTANCES` and at least one instance has been idle for the window,
//! stop the most-recently-scaled (LIFO) instance. Never below
//! `MIN_INSTANCES`; the base instance (lowest port) is never retired
//! while count > min.
//!
//! All thresholds are pinned to never-scale values in `catalog.rs`
//! auto-scaling is disabled by default (2026-08 retune; design ).

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use crate::config::CaptainConfig;
use crate::store::{self, ServiceInstance};
use crate::supervisor;

/// Track how long each service type has been continuously busy (for
/// scale-up) and each instance has been continuously idle (for scale-down).
fn busy_since() -> &'static Mutex<HashMap<String, Instant>> {
    static B: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    B.get_or_init(|| Mutex::new(HashMap::new()))
}
fn idle_since() -> &'static Mutex<HashMap<String, Instant>> {
    static I: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    I.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Scale-up decision seam: a service type is busy when **all** of its
/// `Active` instances exceed one of the busy thresholds.
/// Handle all busy.
pub fn all_busy(instances: &[ServiceInstance]) -> bool {
    !instances.is_empty()
        && instances.iter().all(|i| {
            i.cpu_avg_1m > crate::catalog::BUSY_CPU_PCT
                || i.latency_avg_1m_ms > crate::catalog::BUSY_LATENCY_MS
        })
}

/// Scale-down decision seam: an instance is idle when under **both** idle
/// thresholds.
/// Handle is idle.
pub fn is_idle(inst: &ServiceInstance) -> bool {
    inst.cpu_avg_1m < crate::catalog::IDLE_CPU_PCT
        && inst.latency_avg_1m_ms < crate::catalog::IDLE_LATENCY_MS
}

/// LIFO retirement seam: pick the scale-down target - the most-recently
/// started non-base instance (base = lowest port for this service type).
/// Returns `None` when only the base instance exists or no candidate has
/// a live pid.
/// Handle lifo target.
pub fn lifo_target(started: &[ServiceInstance]) -> Option<ServiceInstance> {
    let base_port = started.iter().map(|i| i.local_port).min().unwrap_or(0);
    started
        .iter()
        .filter(|i| i.local_port != base_port && i.pid != 0)
        .max_by_key(|i| i.started_at.unwrap_or(0))
        .cloned()
}

/// Port-allocation seam: scan the global range for the first port not
/// claimed by a live instance and not held by a foreign process. Pure
/// over the caller-supplied used-port set and port-in-use predicate so
/// TEST-2 can pin the no-double-allocate policy.
/// Handle pick free port.
pub fn pick_free_port(
    used: &std::collections::HashSet<u16>,
    range: (u16, u16),
    port_in_use: impl Fn(u16) -> bool,
) -> Option<u16> {
    for p in range.0..=range.1 {
        if used.contains(&p) {
            continue;
        }
        if port_in_use(p) {
            continue;
        }
        return Some(p);
    }
    None
}

/// Handle evaluate.
pub async fn evaluate(
    conn: &glide::GlideClient,
    config: &CaptainConfig,
) -> Result<(), anyhow::Error> {
    let instances = store::list_for_ip(conn, &config.local_ip).await?;

    // Group active instances by service type. The monitor promotes
    // `Starting` → `Active` in one tick - `Started` is never produced
    // so the scaler's busy/idle decisions run over `Active` instances.
    let mut by_type: HashMap<String, Vec<ServiceInstance>> = HashMap::new();
    for inst in &instances {
        if inst.status == "Active" {
            by_type
                .entry(inst.service_type.clone())
                .or_default()
                .push(inst.clone());
        }
    }

    // ── Machine capacity (aggregate CPU/mem across all Active rows) ──
    let (agg_cpu, agg_mem, n) = instances
        .iter()
        .filter(|i| i.status == "Active")
        .fold((0.0f32, 0.0f32, 0u32), |(c, m, n), i| {
            (c + i.cpu_avg_1m, m + i.memory_avg_1m, n + 1)
        });
    let agg_cpu = if n > 0 { agg_cpu / n as f32 } else { 0.0 };
    let agg_mem = if n > 0 { agg_mem / n as f32 } else { 0.0 };

    // ── Scale-up check ──────────────────────────────────────────────────
    for (service_type, started) in &by_type {
        let entry = match config.catalog.get(service_type) {
            // Placement gate (FLEET-1, DESIGN §11.3): the scaler has no
            // machine choice to make - a constrained service that does not
            // admit a second instance on THIS machine (pin to elsewhere,
            // anti violated, singleton) never scales here. Multi-machine
            // placement is the provisioner + remote-spawn plane's job.
            Some(e) => {
                let local_obs: Vec<crate::placement::ObservedInstance> = instances
                    .iter()
                    .filter(|i| i.status != "Stopped" && i.status != "Killed")
                    .map(|i| crate::placement::ObservedInstance {
                        ip: i.local_ip.clone(),
                        service_type: i.service_type.clone(),
                    })
                    .collect();
                let fleet_obs: Vec<crate::placement::ObservedInstance> = local_obs.clone();
                if let Err(refusal) =
                    crate::placement::placement_admits(e, &config.local_ip, &local_obs, &fleet_obs)
                {
                    tracing::debug!(
                        service = %service_type,
                        placement = %e.placement,
                        reason = refusal.as_str(),
                        "scaler: placement-constrained service - scale-up skipped"
                    );
                    continue;
                }
                e
            }
            None => continue,
        };
        // Busy if ALL started instances are over a busy threshold.
        let all_busy = all_busy(started);
        // Decide under the lock whether the service is eligible to scale
        // up this tick, then DROP the lock before any await so the task
        // stays `Send`.
        let should_scale_up = {
            let mut bs = busy_since().lock().unwrap();
            if all_busy {
                let since = bs.entry(service_type.clone()).or_insert_with(Instant::now);
                since.elapsed().as_secs() >= crate::catalog::BUSY_WINDOW_S
            } else {
                bs.remove(service_type);
                false
            }
        };
        if should_scale_up {
            // Capacity check.
            let machine_ok = agg_cpu < crate::catalog::MACHINE_CPU_CAP_PCT
                && agg_mem < crate::catalog::MACHINE_MEM_CAP_PCT;
            let count = store::count_for_type_on_ip(conn, service_type, &config.local_ip).await?;
            if !machine_ok {
                supervisor::alert_capacity(service_type);
                if let Ok(mut bs) = busy_since().lock() {
                    bs.remove(service_type);
                }
            } else if (count as u8) < crate::catalog::MAX_INSTANCES {
                // Auto-assign the next free port from the GLOBAL range
                // (config.port_range), not a per-service range. The second
                // instance of any service gets the next available port
                // globally - ports are shared across all services on this
                // machine.
                if let Some(port) = next_free_port(conn, &config.local_ip, config.port_range).await
                {
                    let new_inst = ServiceInstance {
                        key: ServiceInstance::make_key(service_type, &config.local_ip, port),
                        service_type: service_type.clone(),
                        local_ip: config.local_ip.clone(),
                        local_port: port,
                        pid: 0,
                        start_priority: entry.start_priority,
                        cpu_avg_1m: 0.0,
                        memory_avg_1m: 0.0,
                        rss_mb_avg_1m: 0.0,
                        latency_avg_1m_ms: 0.0,
                        last_health_check: None,
                        status: "Starting".to_string(),
                        restarts: 0,
                        started_at: None,
                        // CAPTAIN-10: empty seed - captured by the first probe.
                        version: String::new(),
                        build_hash: String::new(),
                        errors: 0,
                        warnings: 0,
                        api_calls: 0,
                    };
                    store::upsert_instance(conn, &new_inst).await?;
                    match supervisor::spawn(conn, &new_inst, entry, port, None).await {
                        Ok(pid) => tracing::info!(
                            service = service_type,
                            port,
                            pid,
                            "scaled up to instance"
                        ),
                        Err(e) => tracing::error!(error = ?e, "scale-up spawn failed"),
                    }
                }
            }
        }
    }

    // ── Scale-down check ───────────────────────────────────────────────
    for (service_type, started) in &by_type {
        if !config.catalog.contains_key(service_type) {
            continue;
        }
        let count = store::count_for_type_on_ip(conn, service_type, &config.local_ip).await? as u8;
        if count <= crate::catalog::MIN_INSTANCES {
            let mut is = idle_since().lock().unwrap();
            is.retain(|k, _| started.iter().any(|s| &s.key == k));
            continue;
        }
        // Track idle-since per instance. Collect a stop target (if any)
        // under the lock, then drop the lock BEFORE awaiting `stop` so the
        // async block stays `Send`. The locked section is wrapped in a
        // block so the guard's lifetime ends before any await.
        let (stop_target, to_clear) = {
            let mut is = idle_since().lock().unwrap();
            is.retain(|k, _| started.iter().any(|s| &s.key == k));
            let mut stop_target: Option<(ServiceInstance, u32)> = None;
            let mut to_clear = None;
            for inst in started {
                let idle = is_idle(inst);
                if idle {
                    let since = is.entry(inst.key.clone()).or_insert_with(Instant::now);
                    let idle_for = since.elapsed().as_secs();
                    if idle_for >= crate::catalog::IDLE_WINDOW_S {
                        // LIFO: retire the most-recently-scaled instance,
                        // but never the base instance (the one with the
                        // lowest port for this service type - it was the
                        // first to be auto-assigned).
                        if let Some(target) = lifo_target(started) {
                            let pid = target.pid;
                            tracing::info!(
                                service = service_type,
                                port = target.local_port,
                                pid,
                                "scaling down idle instance"
                            );
                            stop_target = Some((target, pid));
                            to_clear = Some(inst.key.clone());
                            break;
                        }
                    }
                } else {
                    is.remove(&inst.key);
                }
            }
            (stop_target, to_clear)
        };
        if let Some((inst, pid)) = stop_target {
            if let Some(entry) = config.catalog.get(&inst.service_type) {
                let _ = supervisor::stop(
                    conn,
                    &inst,
                    entry,
                    pid,
                    crate::catalog::GRACE_PERIOD_S,
                    config.upgrade_drain_s,
                )
                .await;
            }
        }
        if let Some(key) = to_clear {
            if let Ok(mut m) = idle_since().lock() {
                m.remove(&key);
            }
        }
        continue;
    }
    Ok(())
}

/// Find the next free port from the GLOBAL range. `store::next_free_port`
/// no longer exists (Valkey-backed), so we scan `list_for_ip` results for
/// already-used ports and fall back to `server::is_port_in_use` for any
/// port held by a process not (yet) recorded in Valkey.
/// Handle next free port.
pub async fn next_free_port(
    conn: &glide::GlideClient,
    local_ip: &str,
    range: (u16, u16),
) -> Option<u16> {
    let instances = store::list_for_ip(conn, local_ip).await.ok()?;
    // Only live instances occupy a port - Stopped/Killed instances have
    // been (or are about to be) deleted, so their ports are reusable.
    let used: std::collections::HashSet<u16> = instances
        .iter()
        .filter(|i| i.status != "Stopped" && i.status != "Killed")
        .map(|i| i.local_port)
        .collect();
    pick_free_port(&used, range, crate::server::is_port_in_use)
}

/// Reservation TTL - a crashed upgrade self-releases after this window.
/// Upgrades normally release their reservation as soon as the spawned
/// instance is registered (the registry row then guards the port) or on
/// any abort path.
const PORT_RESERVE_TTL_S: u64 = 60;

/// Release a port reservation acquired by [`reserve_free_port`].
/// Missing key is not an error (double-release is a no-op).
/// Handle release reserved port.
pub async fn release_reserved_port(conn: &glide::GlideClient, local_ip: &str, port: u16) {
    let key = format!("captain:port:reserve:{}:{}", local_ip, port);
    let _: () = glide::cmd("DEL")
        .arg(&key)
        .query_async(conn)
        .await
        .unwrap_or(());
}

/// Find AND atomically reserve the next free port for a rolling upgrade
/// .
///
/// `next_free_port` alone is scan-then-spawn: two concurrent upgrades can
/// both observe the same free port and collide - every spawn fails to
/// bind and the upgrades abort with `did not become Active` while the
/// monitor crash-loops the children. This wrapper adds a Valkey
/// reservation (`SET NX EX captain:port:reserve:{ip}:{port}`) on top of
/// the registry + OS scan: a candidate is only returned if the NX acquire
/// succeeds. The caller MUST either let the spawn register the instance
/// (making the registry the durable guard) or call
/// [`release_reserved_port`] on abort; the EX TTL is the crashed-process
/// backstop.
/// Handle reserve free port.
pub async fn reserve_free_port(
    conn: &glide::GlideClient,
    local_ip: &str,
    range: (u16, u16),
) -> Option<u16> {
    let instances = store::list_for_ip(conn, local_ip).await.ok()?;
    let used: std::collections::HashSet<u16> = instances
        .iter()
        .filter(|i| i.status != "Stopped" && i.status != "Killed")
        .map(|i| i.local_port)
        .collect();
    for port in range.0..=range.1 {
        if used.contains(&port) || crate::server::is_port_in_use(port) {
            continue;
        }
        // Atomic acquire - concurrent upgrades cannot take the same port.
        let key = format!("captain:port:reserve:{}:{}", local_ip, port);
        let acquired: Option<()> = glide::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(PORT_RESERVE_TTL_S)
            .query_async(conn)
            .await
            .ok();
        if acquired.is_some() {
            return Some(port);
        }
    }
    None
}
