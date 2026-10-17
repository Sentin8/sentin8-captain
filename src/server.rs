// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup + startup reconcile + priority-tiered spawn.
//!
//! Startup flow:
//! 1. Connect to Valkey (the service registry needs no Auth /
//! mTLS / OAuth bootstrap).
//! 2. Acquire an advisory lock (SET NX EX 30 + PID file).
//! 3. Clean stale terminal states + crash-reconcile.
//! 4. Spawn all services tier-by-tier (bounded concurrency within a
//! tier, 3s pause between tiers), registering each instance in
//! Valkey immediately after spawning.
//! 5. Start the monitor loop (3s default tick).
//! 6. Serve the management API (bound before spawning so `make status`
//! works while services are still starting).
//!
//! Shutdown: only `POST /v1/captain/shutdown` (called by `sentin8 captain stop`)
//! triggers a full graceful shutdown — it stops all managed services,
//! releases the advisory lock, and exits. SIGTERM/SIGINT just exit the
//! process immediately (services keep running, the lock auto-expires).

use std::sync::{Arc, RwLock};

use axum::routing::{get, post};
use tokio::sync::watch;
use tower_http::cors::CorsLayer;

use crate::config::CaptainConfig;
use crate::handlers::{self, AppState};
use crate::local;
use crate::store;

/// Serve it.
pub async fn serve(
    config: CaptainConfig,
    addr: String,
    _tls: sentin8::tls::Sentin8Tls,
) -> anyhow::Result<()> {
    // ── 1. Connect to Valkey (Valkey certificate identity — group DESIGN.md
    // §3.1). The supervisor must boot even when the Valkey identity is
    // still minting (a fresh boot: acme is not up yet and the background
    // mint loop lands the pair seconds later) or when Valkey itself is
    // down — BOTH the pair-read and the handshake retry here, and every
    // Valkey-touching path behind them degrades the same way.
    let conn = {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
        loop {
            match sentin8::middleware::valkey_client(&config.valkey_url, "sentin8:captain").await {
                Ok(c) => break c,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "captain: Valkey identity/connection not ready at boot — \
                         retrying (the supervisor must boot Valkey-down; the mint \
                         loop and the plane converge in the background)"
                    );
                }
            }
            if std::time::Instant::now() > deadline {
                anyhow::bail!("captain: Valkey unreachable for 10 minutes — giving up");
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    };

    // ── 2. Acquire exclusivity (advisory lock via SETNX + PID file) ──
    if !store::try_advisory_lock(&conn, &config.local_ip).await? {
        anyhow::bail!(
            "another captain is already running on this IP ({}) — advisory lock held",
            config.local_ip
        );
    }
    // Write the PID file (FHS: /run/sentin8/captain.pid, dev: .run/captain.pid).
    // The directory is created if missing. On shutdown we remove it.
    let pid_file = sentin8::config::captain_pid_file();
    if let Some(parent) = std::path::Path::new(&pid_file).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(&pid_file, format!("{}\n", std::process::id())) {
        tracing::warn!(error = %e, path = %pid_file, "failed to write captain PID file");
    } else {
        tracing::debug!(path = %pid_file, pid = std::process::id(), "wrote captain PID file");
    }

    // ── 2b. Clean up stale terminal-state instances from previous run ─
    match store::cleanup_terminal_states(&conn, &config.local_ip).await {
        Ok(n) if n > 0 => tracing::info!(removed = n, "cleaned up stale Stopped/Killed instances"),
        _ => {}
    }

    // ── 2c. Register captain itself as a service instance ─────────────
    // Captain registers itself so other captain instances (on other machines)
    // can discover it for future inter-captain communication (rolling
    // upgrades, cluster coordination, etc.). One instance per machine.
    {
        let orch_inst = store::ServiceInstance {
            key: store::ServiceInstance::make_key("sentin8:captain", &config.local_ip, config.port),
            service_type: "sentin8:captain".to_string(),
            local_ip: config.local_ip.clone(),
            local_port: config.port,
            pid: std::process::id(),
            start_priority: 0,
            cpu_avg_1m: 0.0,
            memory_avg_1m: 0.0,
            rss_mb_avg_1m: 0.0,
            latency_avg_1m_ms: 0.0,
            last_health_check: Some(chrono::Utc::now().timestamp()),
            status: "Active".to_string(),
            restarts: 0,
            started_at: Some(chrono::Utc::now().timestamp()),
            version: sentin8::build_info::id(),
            build_hash: sentin8::build_info::build_hash().to_string(),
            errors: 0,
            warnings: 0,
            api_calls: 0,
        };
        let _ = store::upsert_instance(&conn, &orch_inst).await;
        tracing::info!(
            port = config.port,
            pid = std::process::id(),
            "captain registered itself in Valkey"
        );
    }

    // ── 3. Bind the HTTP listener and start serving immediately ──────
    // The API must be responsive right away — `sentin8 captain services`
    // should work even while services are still spawning.
    let local_ip = config.local_ip.clone();
    let shutdown_config = config.clone();

    // Shutdown channel: the POST /v1/captain/shutdown handler sends `true`
    // to trigger the full graceful shutdown (stop all services + exit).
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // ── Sentin8:Policy (Phase ): boot load refuses to start on invalid
    // policy text; hot-reload via the shared direct consumer; shared deps for
    // live identity resolution; stat emitter. Captain's own DB access is via
    // the store's Valkey connection — the policy tables live in PG.
    // URL resolution matches the shell boot (SENTIN8_CAPTAIN_DATABASE_URL →
    // DATABASE_URL → default): a hardcoded `default_database_url` connected
    // as sentin8_app, whose RLS hides every policy row without a tenant
    // context — the engine loaded 0 sets and denied everything fail-closed
    // (COLD-START-1).
    let captain_db_url = std::env::var("SENTIN8_CAPTAIN_DATABASE_URL")
        .ok()
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .unwrap_or_else(|| sentin8::config::Sentin8Config::default_database_url().to_string());
    // ── Sentin8:Policy (— boot_full): captain is a
    // custom-boot binary (process supervisor, no shell serve), so it runs
    // the ONE shared boot helper itself — same four steps the shell runs
    // for every other service (boot_full uses the boot-loader function
    // policy design -r — so the COLD-START-1 RLS gap is closed here
    // too: the sentin8_app role sees 0 rows without tenant context).
    let pg_pool = sentin8::config::pg_pool::connect(&captain_db_url).await?;
    let policy_engine = crate::policy::engine();
    crate::policy::boot_full(
        &pg_pool,
        &sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer(),
        "sentin8:captain",
        &policy_engine,
    )
    .await?;

    let state = AppState {
        config: Arc::new(config.clone()),
        admin: sentin8::shield::admin::SharedAdminState {
            service: "sentin8:captain".to_string(),
            pool: pg_pool.clone(),
            policy: policy_engine.clone(),
            // The admin surface's auth client verifies operator Bearer tokens
            // against Sentin8:Auth — it needs the platform issuer URL.
            // `ClientOptions::default` carries an EMPTY base_url, which made
            // every token verification fail with a reqwest "builder error"
            // (COLD-START-1).
            auth_client: std::sync::Arc::new(sentin8::auth::client::Client::new(
                sentin8::auth::client::ClientOptions {
                    base_url: sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer(),
                    ..Default::default()
                },
            )),
        },
        policy: policy_engine,
        live_catalog: Arc::new(RwLock::new(config.catalog.clone())),
        conn: conn.clone(),
        shutdown_tx,
    };
    // The TCP router consumes `state`; the UDS router needs its
    // own clone — take it before the move below.
    let state_for_uds = state.clone();

    // Clone live_catalog before state is moved into the router.
    let live_catalog_for_monitor = state.live_catalog.clone();

    let app = axum::Router::new()
        .route("/v1/health", get(handlers::health))
        .route("/v1/captain/shutdown", post(handlers::shutdown))
        .route("/v1/captain/services", get(handlers::list_services))
        .route("/v1/captain/machines", get(handlers::list_machines))
        .route("/v1/captain/autoscaler", get(handlers::autoscaler_status))
        .route(
            "/v1/captain/autoscaler/approve",
            post(handlers::autoscaler_approve),
        )
        // Admin UI (RFW) — rendered by the dash at runtime. The
        // approve/reject row-action endpoints expose the same Shield-gated
        // decision path as the HTTP API.
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        .route("/v1/admin/{resource}", get(crate::admin_ui::get_admin_data))
        .route(
            "/v1/admin/autoscaler-approve/{id}",
            post(crate::admin_ui::approve_row),
        )
        .route(
            "/v1/admin/autoscaler-reject/{id}",
            post(crate::admin_ui::reject_row),
        )
        .route("/v1/captain/services/{key}", get(handlers::get_service))
        .route("/v1/captain/services/{key}", post(handlers::service_action))
        .route(
            "/v1/captain/upgrade-status/{key}",
            get(handlers::upgrade_status),
        )
        .route(
            "/v1/captain/upgrade-stream/{key}",
            get(handlers::upgrade_stream),
        )
        .route("/v1/captain/startup-stream", get(handlers::startup_stream))
        .route(
            "/v1/captain/shutdown-stream",
            get(handlers::shutdown_stream),
        )
        .route("/v1/captain/catalog", get(handlers::list_catalog))
        .route("/v1/captain/merge-catalog", post(handlers::merge_catalog))
        .route("/v1/captain/start-services", post(handlers::start_services))
        .route("/v1/captain/instances", post(handlers::remote_instances))
        .route("/v1/captain/readiness", get(handlers::readiness))
        .route("/v1/captain/alerts", get(handlers::list_alerts))
        // Anti-spoofing : the kernel-proven local-peer header is
        // injected only by the UDS accept loop — a client-supplied copy
        // arriving over TCP is stripped before any handler sees it.
        .layer(axum::middleware::from_fn(local::strip_local_peer_header))
        .layer(axum::middleware::from_fn(
            sentin8::middleware::sentin8_tls_context,
        ))
        .layer(axum::middleware::from_fn(
            sentin8::middleware::request_logging,
        ))
        .layer(axum::middleware::from_fn(
            sentin8::middleware::correlation_id,
        ))
        .layer(CorsLayer::very_permissive())
        .with_state(state);

    // ── 3b. Local control channel : the same router on a
    // Unix domain socket, authorized by kernel-proven peer credentials
    // (root or socket owner) instead of a Bearer token. The TCP listener
    // above keeps the full Shield gate — the LAN RCE surface is
    // untouched. TLS-context middleware is deliberately NOT applied on
    // the UDS router: its X-Sentin8-* injection contract is TLS-specific
    // and a local peer presents no TLS context.
    let local_listener = local::bind_local_socket()?;
    let local_router = local_listener.as_ref().map(|_| {
        axum::Router::new()
            .route("/v1/health", get(handlers::health))
            .route("/v1/captain/shutdown", post(handlers::shutdown))
            .route("/v1/captain/services", get(handlers::list_services))
            .route("/v1/captain/machines", get(handlers::list_machines))
            .route("/v1/captain/alerts", get(handlers::list_alerts))
            .route("/v1/captain/autoscaler", get(handlers::autoscaler_status))
            .route(
                "/v1/captain/autoscaler/approve",
                post(handlers::autoscaler_approve),
            )
            // Admin UI routes are NOT served on the UDS control channel
            // the dash consumes the API over the network via the BFF proxy;
            // the socket is a local lifecycle-control surface.
            .route("/v1/captain/services/{key}", get(handlers::get_service))
            .route("/v1/captain/services/{key}", post(handlers::service_action))
            .route(
                "/v1/captain/upgrade-status/{key}",
                get(handlers::upgrade_status),
            )
            .route(
                "/v1/captain/upgrade-stream/{key}",
                get(handlers::upgrade_stream),
            )
            .route("/v1/captain/startup-stream", get(handlers::startup_stream))
            .route(
                "/v1/captain/shutdown-stream",
                get(handlers::shutdown_stream),
            )
            .route("/v1/captain/catalog", get(handlers::list_catalog))
            .route("/v1/captain/merge-catalog", post(handlers::merge_catalog))
            .route("/v1/captain/start-services", post(handlers::start_services))
            .route("/v1/captain/instances", post(handlers::remote_instances))
            .route("/v1/captain/readiness", get(handlers::readiness))
            .layer(axum::middleware::from_fn(
                sentin8::middleware::request_logging,
            ))
            .layer(axum::middleware::from_fn(
                sentin8::middleware::correlation_id,
            ))
            .with_state(state_for_uds.clone())
    });

    let addr_clone = addr.clone();
    tracing::info!("captain listening on {addr}");

    // ── 4. Spawn services in the background (non-blocking) ───────────
    // Services are spawned asynchronously so the API stays responsive.
    // Each instance is registered in Valkey immediately after spawning
    // so `sentin8 captain services` shows them as they come up.
    {
        let config_bg = config.clone();
        let conn_bg = conn.clone();
        tokio::spawn(async move {
            start_and_register_all(&conn_bg, &config_bg).await;
        });
    }

    // ── 5. Start the monitor loop ─────────────────────────────────────
    crate::monitor::spawn(conn.clone(), config.clone(), live_catalog_for_monitor);

    // ── 6. Serve until shutdown ───────────────────────────────────────
    // Captain serves plain HTTP (not via sentin8-tls) because it is the process
    // supervisor — it must be reachable before any service's sentin8-tls can
    // obtain certs from Acme. Proxy routes captain traffic directly.
    let listener = tokio::net::TcpListener::bind(&addr_clone).await?;

    // Local UDS control channel task — serves the same router.
    if let (Some((uds_listener, socket_owner)), Some(local_app)) = (local_listener, local_router) {
        let local_shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            local::serve_local(uds_listener, socket_owner, local_app, local_shutdown).await;
        });
    }

    let server_handle = tokio::spawn({
        let listener = listener;
        let app = app;
        let mut shutdown_rx_clone = shutdown_rx.clone();
        async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    // Wait for the shutdown signal from the POST
                    // /v1/captain/shutdown handler (or a signal). When
                    // this future resolves, axum stops accepting new
                    // connections and finishes in-flight requests.
                    let _ = shutdown_rx_clone.changed().await;
                })
                .await
        }
    });

    // Wait for the shutdown trigger (or signal).
    {
        let mut rx = shutdown_rx.clone();
        let sig = sentin8::middleware::shutdown_signal("sentin8:captain");
        tokio::pin!(sig);
        tokio::select! {
                   _ = &mut sig => {
        // Signal — just exit, services keep running.
        // Abort the server task and exit immediately.
                       server_handle.abort();
                       tracing::info!("captain received signal — exiting (services keep running, lock will auto-expire)");
                       return Ok(());
                   }
                   _ = rx.changed() => {
        // Shutdown endpoint — run full graceful shutdown below.
        // The watch channel also fires the axum server's graceful
        // shutdown future, so it stops accepting new connections
        // while in-flight requests (like `make status`) drain.
                   }
               }
    }

    // ── Full graceful shutdown: stop all managed services ─────────
    // The HTTP server is draining in-flight requests — `make status`
    // can query the status transitions while we stop services.
    tracing::info!("captain shutdown requested via API — stopping all managed services");
    crate::monitor::set_shutting_down();
    shutdown_all_services(&conn, &shutdown_config).await;
    // Release the autoscaler leader lock — the 30s TTL would
    // expire on its own, but releasing immediately lets another captain
    // take the provisioning role without waiting.
    crate::provision::shutdown_cleanup(&conn).await;
    let _ = store::release_advisory_lock(&conn, &local_ip).await;

    // Remove the PID file and the local control socket.
    let pid_file = sentin8::config::captain_pid_file();
    let _ = std::fs::remove_file(&pid_file);
    local::remove_local_socket();

    // Remove the bootstrap enrollment credential — the enrollment
    // channel is only alive while THIS captain process brokers it; the
    // next boot regenerates a fresh secret (the sealed at-rest file must
    // never outlive the fleet it was minted for).
    crate::bootstrap::clear_enrollment();

    // Wait for the HTTP server to finish draining in-flight requests.
    // This returns quickly now that the graceful_shutdown future resolves
    // on the shutdown_rx signal (was previously pending → 60s hang).
    let _ = server_handle.await;
    tracing::info!("captain shutdown complete");

    Ok(())
}

/// Stop all managed services gracefully on shutdown.
/// Sets each Active/Started instance to Inactive (drain), waits briefly
/// for traffic to drain, then sends SIGTERM and polls for exit (up to
/// grace period), SIGKILL any survivors.
async fn shutdown_all_services(conn: &glide::GlideClient, config: &CaptainConfig) {
    let instances = match store::list_for_ip(conn, &config.local_ip).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = ?e, "shutdown: failed to list instances");
            return;
        }
    };

    // Collect PIDs to stop (skip captain itself).
    let to_stop: Vec<_> = instances
        .iter()
        .filter(|i| i.service_type != "sentin8:captain" && i.pid != 0)
        .collect();

    // : Set all Active/Started instances to Inactive (drain).
    for inst in &to_stop {
        if inst.status == "Active" || inst.status == "Started" || inst.status == "Starting" {
            let _ = store::mark_inactive(conn, inst).await;
            tracing::info!(
                service = %inst.service_type,
                pid = inst.pid,
                "shutdown: set to Inactive (draining)"
            );
        }
    }

    // : Brief drain wait (3s) for in-flight requests.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // : SIGTERM all live instances.
    for inst in &to_stop {
        if crate::procfs::pid_alive(inst.pid) {
            let _ = store::mark_stopping(conn, inst).await;
            let _ = unsafe { kill_signal(inst.pid, 15) };
            tracing::info!(service = %inst.service_type, pid = inst.pid, "shutdown: SIGTERM sent");
        }
    }

    // : Poll for exit every 500ms (up to 10s grace).
    // Most services exit immediately on SIGTERM — no need to wait the
    // full grace period if they're all gone.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let all_dead = to_stop
            .iter()
            .all(|inst| !crate::procfs::pid_alive(inst.pid));
        if all_dead || std::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    // : SIGKILL any survivors.
    for inst in &to_stop {
        if crate::procfs::pid_alive(inst.pid) {
            let _ = unsafe { kill_signal(inst.pid, 9) };
            tracing::warn!(service = %inst.service_type, pid = inst.pid, "shutdown: SIGKILL (did not exit gracefully)");
        }
        let _ = store::mark_stopped(conn, inst).await;
        // Remove the stopped instance so its port is freed for the next run.
        let _ = store::delete_instance(conn, inst).await;
    }

    // Also remove captain's own instance from Valkey.
    for inst in &instances {
        if inst.service_type == "sentin8:captain" {
            let _ = store::delete_instance(conn, inst).await;
            break;
        }
    }

    tracing::info!("all managed services stopped");
}

/// A service that was spawned before DB access was available.
struct SpawnedService {
    service_type: String,
    local_port: u16,
    pid: u32,
    start_priority: i16,
}

/// Spawn all services and register each one in Valkey **immediately** after
/// it spawns — not in a batch after all spawns complete. This way
/// `sentin8 captain services` / `make status` shows instances progressively
/// during the startup sequence (which can take 30+ seconds with spawn
/// delays).
async fn start_and_register_all(conn: &glide::GlideClient, config: &CaptainConfig) {
    // Crash-reconcile stale instances from a previous run first.
    // SELFUP- : the returned map is BINDING
    // adopted service types are skipped below and their ports pre-seeded,
    // so a post-crash start converges to one fleet instead of spawning a
    // duplicate beside the orphans (the prior sweep adoption was log-only).

    let mut used_ports: std::collections::HashSet<u16> = std::collections::HashSet::new();
    // Adopted orphans hold their ports — the allocator must not hand them
    // to a fresh spawn, and their service types must not be spawned again.
    let adopted = reconcile_existing(conn, config).await.unwrap_or_default();
    for a in adopted.values() {
        used_ports.insert(a.local_port);
    }

    // Sort catalog entries by start_priority so lower-priority services
    // get the lowest ports.
    let mut entries: Vec<(&String, &crate::catalog::ServiceCatalogEntry)> =
        config.catalog.iter().collect();
    entries.sort_by_key(|(_, e)| e.start_priority);

    let sem = Arc::new(tokio::sync::Semaphore::new(config.start_concurrency.max(1)));
    let mut count = 0;
    let mut last_priority: Option<i16> = None;
    // D6 (RS §3): instances spawned in the current tier — the tier gate
    // waits for these to reach Active before the next tier starts.
    let mut tier_spawned: Vec<(String, u16)> = Vec::new();

    for (service_type, entry) in &entries {
        // Skip captain itself — it's already running (this process).
        // The catalog entry exists only so the monitor loop samples
        // captain's own CPU/memory.
        if *service_type == "sentin8:captain" {
            continue;
        }
        // Boot-spawn allow-list (DESIGN §3 "Catalog and the boot-spawn
        // filter"): `SENTIN8_SERVICES` gates ONLY this loop — the catalog
        // itself stays the full union, so /start-services and per-instance
        // actions can start pruned-at-boot types later without a captain
        // restart.
        if let Some(allow) = &config.boot_allow {
            if !allow.contains(*service_type) {
                tracing::info!(
                    service = %service_type,
                    "boot spawn skipped — not in SENTIN8_SERVICES boot allow-list"
                );
                continue;
            }
        }
        // SELFUP- : an adopted orphan already
        // serves this type — spawning a second instance would duplicate it.
        if let Some(a) = adopted.get(*service_type) {
            tracing::info!(
                service = %service_type,
                port = a.local_port,
                pid = a.pid,
                "skipping spawn — adopted orphaned instance already serving this type"
            );
            continue;
        }
        // D6 (RS §3): tier boundary — HEALTH-GATED, not a flat 3s sleep.
        // Wait for every instance spawned in the previous tier to report
        // Active before starting the next tier (bounded by the gate
        // timeout; on timeout warn + proceed — degraded old behavior,
        // never a boot hang). Services are fail-open by design, so the
        // gate is a fast-path optimization, not a correctness crutch.
        if let Some(prev) = last_priority {
            if entry.start_priority != prev {
                wait_for_tier_active(conn, config, &tier_spawned).await;
                tier_spawned.clear();
            }
        }
        last_priority = Some(entry.start_priority);

        let svc = service_type.to_string();
        let entry_clone = (*entry).clone();

        // Placement gate (FLEET-1, DESIGN §11.3): every spawn site consults
        // the same seam. At boot this is how machine B spawns its correct
        // subset WITHOUT a per-machine SENTIN8_SERVICES list — a pin to
        // another machine skips the spawn, an anti/singleton violation
        // skips with a warning. Failures here are skips, not boot errors:
        // the machine that owns the placement spawns it.
        {
            let conn_obs = conn.clone();
            let all = store::list_all(&conn_obs).await.unwrap_or_default();
            let local_obs: Vec<crate::placement::ObservedInstance> = all
                .iter()
                .filter(|i| i.local_ip == config.local_ip)
                .filter(|i| i.status != "Stopped" && i.status != "Killed")
                .map(|i| crate::placement::ObservedInstance {
                    ip: i.local_ip.clone(),
                    service_type: i.service_type.clone(),
                })
                .collect();
            let fleet_obs: Vec<crate::placement::ObservedInstance> = all
                .iter()
                .filter(|i| i.status == "Active")
                .map(|i| crate::placement::ObservedInstance {
                    ip: i.local_ip.clone(),
                    service_type: i.service_type.clone(),
                })
                .collect();
            if let Err(refusal) = crate::placement::placement_admits(
                &entry_clone,
                &config.local_ip,
                &local_obs,
                &fleet_obs,
            ) {
                tracing::info!(
                    service = %svc,
                    placement = %entry_clone.placement,
                    reason = refusal.as_str(),
                    detail = refusal.reason(),
                    "boot spawn skipped — placement gate refused this machine"
                );
                continue;
            }
        }

        // Workers now get a real port + /v1/health listener like any
        // service, so they use the same port-assignment + spawn path.
        // (They have no inbound traffic beyond the health probe.)

        // Fixed-port services (e.g. proxy on 443) always get their
        // configured port — not auto-assigned from the global range.
        let port = if entry_clone.fixed_port > 0 {
            entry_clone.fixed_port
        } else {
            // Auto-assign the next free port from the global range.
            let mut p = config.port_range.0;
            while used_ports.contains(&p) || is_port_in_use(p) {
                p = match p.checked_add(1) {
                    Some(pp) if pp <= config.port_range.1 => pp,
                    _ => break,
                };
            }
            if p > config.port_range.1 {
                tracing::warn!(service = service_type, "port range exhausted — skipping");
                continue;
            }
            p
        };

        // Adoption check: if the port is already in use (by a process
        // that's NOT us), check if it's the expected service binary
        // already running. This handles the case where the Makefile
        // started log on 3199 before captain — captain should adopt it
        // rather than spawn a duplicate.
        if is_port_in_use(port) {
            if let Some(pid) = pid_on_port(port) {
                if is_expected_binary(pid, &entry_clone.binary) {
                    tracing::info!(
                        service = %svc,
                        port,
                        pid,
                        "adopting already-running service on port"
                    );
                    let s = SpawnedService {
                        service_type: svc.clone(),
                        local_port: port,
                        pid,
                        start_priority: entry_clone.start_priority,
                    };
                    register_spawned(conn, config, &s).await;
                    used_ports.insert(port);
                    count += 1;
                    continue;
                }
            }
            // Port is in use by something else — skip to next free port.
            if entry_clone.fixed_port > 0 {
                tracing::warn!(
                    service = %svc,
                    port,
                    "fixed port is in use by another process — cannot adopt, will try to spawn anyway"
                );
            } else {
                // For auto-assigned ports, find the next free one.
                let mut p = port + 1;
                while used_ports.contains(&p) || is_port_in_use(p) {
                    p = match p.checked_add(1) {
                        Some(pp) if pp <= config.port_range.1 => pp,
                        _ => break,
                    };
                }
                if p > config.port_range.1 {
                    tracing::warn!(service = service_type, "port range exhausted — skipping");
                    continue;
                }
                // Re-check adoption for the new port too.
                if is_port_in_use(p) {
                    if let Some(pid) = pid_on_port(p) {
                        if is_expected_binary(pid, &entry_clone.binary) {
                            tracing::info!(
                                service = %svc,
                                port = p,
                                pid,
                                "adopting already-running service on port"
                            );
                            let s = SpawnedService {
                                service_type: svc.clone(),
                                local_port: p,
                                pid,
                                start_priority: entry_clone.start_priority,
                            };
                            register_spawned(conn, config, &s).await;
                            used_ports.insert(p);
                            count += 1;
                            continue;
                        }
                    }
                }
                used_ports.insert(p);
                let sem = sem.clone();
                let task = tokio::spawn(async move {
                    let _permit = sem.acquire().await.ok()?;
                    match crate::supervisor::spawn_no_db(&svc, &entry_clone, p).await {
                        Ok(pid) => {
                            tracing::info!(service = %svc, port = p, pid, "started service");
                            Some(SpawnedService {
                                service_type: svc.clone(),
                                local_port: p,
                                pid,
                                start_priority: entry_clone.start_priority,
                            })
                        }
                        Err(e) => {
                            tracing::error!(service = %svc, error = ?e, "failed to start service");
                            None
                        }
                    }
                });
                if let Ok(Some(s)) = task.await {
                    register_spawned(conn, config, &s).await;
                    // D6: track for the tier gate.
                    tier_spawned.push((s.service_type.clone(), s.local_port));
                    count += 1;
                }
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
                continue;
            }
        }
        used_ports.insert(port);

        let sem = sem.clone();
        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            match crate::supervisor::spawn_no_db(&svc, &entry_clone, port).await {
                Ok(pid) => {
                    tracing::info!(service = %svc, port, pid, "started service");
                    Some(SpawnedService {
                        service_type: svc.clone(),
                        local_port: port,
                        pid,
                        start_priority: entry_clone.start_priority,
                    })
                }
                Err(e) => {
                    tracing::error!(service = %svc, error = ?e, "failed to start service");
                    None
                }
            }
        });
        if let Ok(Some(s)) = task.await {
            register_spawned(conn, config, &s).await;
            // D6: track for the tier gate.
            tier_spawned.push((s.service_type.clone(), s.local_port));
            count += 1;
        }
        // 1-second delay between each spawn to avoid overwhelming the
        // machine with simultaneous process launches.
        // tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    tracing::info!(count, "all services spawned and registered in Valkey");
}

/// D6 (RS §3): health-gated tier boundary — wait for every instance
/// spawned in the previous tier to reach `Active` in the Valkey registry
/// before the next tier starts. Bounded by
/// `SENTIN8_CAPTAIN_TIER_GATE_TIMEOUT` (seconds, default 60); on timeout
/// warn + proceed (degraded flat-sleep behavior, never a boot hang).
/// Services are fail-open by design (outbox parks, DCR retries), so the
/// gate is a fast-path optimization minimizing the parked-event window —
/// not a correctness crutch.
async fn wait_for_tier_active(
    conn: &glide::GlideClient,
    config: &CaptainConfig,
    tier_spawned: &[(String, u16)],
) {
    if tier_spawned.is_empty() {
        return;
    }
    let timeout_secs: u64 = std::env::var("SENTIN8_CAPTAIN_TIER_GATE_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
    tracing::info!(
        services = tier_spawned.len(),
        timeout_secs,
        "tier boundary — waiting for Active (health gate, D6)"
    );
    let mut pending: Vec<(String, u16)> = tier_spawned.to_vec();
    while !pending.is_empty() && tokio::time::Instant::now() < deadline {
        let mut still: Vec<(String, u16)> = Vec::new();
        for (service_type, port) in &pending {
            // The registry is HASH-shaped: key `captain:svc:{service_type}`,
            // field `{ip}:{port}` (the exact shape upsert_instance writes).
            // A bare GET on the field string reads a never-existing string
            // key and made this gate poll `nil` for its whole timeout —
            // every boot degraded to 5 × 60s of pure waiting (the D6 gate
            // never passed once). store::get_instance reads the RIGHT shape.
            let field = store::ServiceInstance::make_key(service_type, &config.local_ip, *port);
            let active = match store::get_instance(conn, service_type, &field).await {
                Ok(Some(inst)) => inst.status == "Active",
                Ok(None) => false,
                Err(e) => {
                    tracing::warn!(error = ?e, service = %service_type, "tier gate: registry read failed");
                    false
                }
            };
            if !active {
                still.push((service_type.clone(), *port));
            }
        }
        pending = still;
        if !pending.is_empty() {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        }
    }
    if pending.is_empty() {
        tracing::info!("tier gate passed — all tier instances Active");
    } else {
        tracing::warn!(
            still_pending = pending.len(),
            timeout_secs,
            "tier gate timeout — proceeding without all instances Active (D6 degraded mode)"
        );
    }
}

/// Register a single spawned service in Valkey immediately. This makes
/// the instance visible to `sentin8 captain services` / `make status` while
/// subsequent services are still spawning.
async fn register_spawned(conn: &glide::GlideClient, config: &CaptainConfig, svc: &SpawnedService) {
    let inst = store::ServiceInstance {
        key: store::ServiceInstance::make_key(&svc.service_type, &config.local_ip, svc.local_port),
        service_type: svc.service_type.clone(),
        local_ip: config.local_ip.clone(),
        local_port: svc.local_port,
        pid: svc.pid,
        start_priority: svc.start_priority,
        cpu_avg_1m: 0.0,
        memory_avg_1m: 0.0,
        rss_mb_avg_1m: 0.0,
        latency_avg_1m_ms: 0.0,
        last_health_check: None,
        status: "Starting".to_string(),
        restarts: 0,
        started_at: Some(chrono::Utc::now().timestamp()),
        // CAPTAIN-10: seed EMPTY version/build — unknown until the first
        // health probe (seeding captain's own pair made `make status` show a
        // duplicated `.` during the startup grace period).
        version: String::new(),
        build_hash: String::new(),
        errors: 0,
        warnings: 0,
        api_calls: 0,
    };
    let _ = store::upsert_instance(conn, &inst).await;
    let _ = store::mark_starting(conn, &inst, svc.pid).await;

    // Set this service's port in captain's own env so it can be referenced
    // later (e.g. SENTIN8_LOG_UDP_PORT for UDP log forwarding). Services that need
    // to reach other services use sentin8::service_discovery (Valkey pub/sub),
    // not these env vars.
    if svc.local_port > 0 && !svc.service_type.contains(':') {
        let port_env = format!("{}_PORT", svc.service_type.to_uppercase());
        std::env::set_var(&port_env, svc.local_port.to_string());
        tracing::debug!(env = %port_env, port = svc.local_port, "set service port env");

        // Also set the management port env var for services that have a
        // health_port offset (e.g. tls, proxy).
        if let Some(entry) = config.catalog.get(&svc.service_type) {
            if entry.health_port > 0 {
                let mgmt_port = svc.local_port + entry.health_port;
                let mgmt_env = format!("{}_MGMT_PORT", svc.service_type.to_uppercase());
                std::env::set_var(&mgmt_env, mgmt_port.to_string());
                tracing::debug!(env = %mgmt_env, port = mgmt_port, "set mgmt port env");
            }
        }

        // When auth starts, no special env override is needed — services
        // retry DCR until tls is ready to proxy the HTTPS call with
        // proper mTLS. The retry count has been increased to handle the
        // startup ordering (tls needs acme cert before it can proxy).
        // SENTIN8_AUTH_ISSUER stays as the tls-proxied HTTPS URL for all auth
        // calls (DCR, token, OIDC, JWKS, SCIM) to preserve org/env headers
        // and mTLS client cert authentication.
    }
}

/// An orphan service process adopted at boot. The service_type is the map
/// key in `reconcile_existing`'s return value, so it isn't stored here.
#[derive(Clone)]
struct AdoptedInstance {
    local_port: u16,
    pid: u32,
}

/// Expected binary name for a service type. Catalog entries carry the
/// authoritative name; when the type is NOT in the catalog (runtime-
/// registered vertical services under a captain booted without
/// --catalog-paths), derive it from the type itself — the vertical
/// convention is `{workspace}::{leaf}` crates producing binaries named
/// without the workspace prefix (`bank8:ledger` → `bank8-ledger`).
/// SELFUP-: a catalog-unknown type is adopt-eligible, never kill-eligible.
pub(crate) fn expected_binary_for(
    service_type: &str,
    entry: Option<&crate::catalog::ServiceCatalogEntry>,
) -> String {
    match entry {
        Some(e) => e.binary.clone(),
        None => service_type.replace(':', "-"),
    }
}

/// Find the lowest TCP port a PID is listening on (Linux, via lsof).
/// Returns `None` when the process has no listener (workers before bind,
/// non-Linux hosts). Used to CORRECT stale registry ports at boot: rolling
/// upgrades move ports, and a row's recorded port can lag the live process.
fn listen_port_of(pid: u32) -> Option<u16> {
    // -a ANDs the selections; -n/-P keep numeric output; -Fn emits
    // `n<addr>:<port>` records (one per socket).
    let output = std::process::Command::new("lsof")
        .args([
            "-a",
            "-n",
            "-P",
            "-p",
            &pid.to_string(),
            "-sTCP:LISTEN",
            "-Fn",
        ])
        .output()
        .ok()?;
    // Collect every listening port and return the minimum (the primary
    // listener binds first at startup).
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut ports: Vec<u16> = stdout
        .lines()
        .filter_map(|l| l.strip_prefix('n'))
        // `n*:8003`, `n127.:8003`, `n[::]:8003` — the port follows the
        // LAST colon in every shape.
        .filter_map(|a| a.rsplit(':').next()?.parse::<u16>().ok())
        .collect();
    ports.sort_unstable();
    ports.first().copied()
}

/// Crash-reconcile: mark stale `Started`/`Active` instances with dead PIDs as `Killed`,
/// and classify live orphans from a previous captain.
///
/// SELFUP-1.2/1.4/ : returns the set of ADOPTED services
/// — live orphan processes (not children of this captain) whose binary
/// matches the expected name for their service type. Their registry rows are
/// kept/corrected (re-keyed when the recorded port no longer matches the
/// process's actual listener) and the caller (start_and_register_all) MUST
/// skip these service types and pre-seed their ports, so a post-crash
/// `captain start` converges to one fleet instead of spawning a duplicate.
/// Kill criteria are narrowed: the ONLY boot-time kill is a live orphan
/// whose process provably runs a different binary than the service type
/// expects (catalog name, or derived `{type with ':' → '-'}` when the type
/// is not in the catalog — a captain booted without vertical catalog paths
/// must never kill a healthy bank8/hotel8 service just because the type is
/// unknown).
async fn reconcile_existing(
    conn: &glide::GlideClient,
    config: &CaptainConfig,
) -> anyhow::Result<std::collections::HashMap<String, AdoptedInstance>> {
    let existing = store::list_for_ip(conn, &config.local_ip).await?;
    let mut adopted: std::collections::HashMap<String, AdoptedInstance> =
        std::collections::HashMap::new();
    for inst in &existing {
        // DUPROW-1 (DESIGN §5.10.2): `Starting` rows are adoptable too.
        // A last-resort/self-heal spawn whose captain died before its
        // monitor tick promoted the row is a LIVE orphan in `Starting` —
        // excluding it here left it invisible to adoption, and the boot
        // spawn loop then minted a duplicate instance for the type. All
        // live-pid, non-terminal rows are classified by the same
        // binary-identity rule; a `Starting` row with a DEAD pid falls
        // through to the crash-reconcile (Killed + deleted) below.
        if inst.status == "Started"
            || inst.status == "Active"
            || inst.status == "Starting"
        {
            let pid = inst.pid;
            if pid != 0 && !crate::procfs::pid_alive(pid) {
                let _ = store::mark_killed(conn, inst).await;
                tracing::warn!(
                    service = %inst.service_type,
                    pid,
                    "crash-reconcile: stale {} instance → Killed",
                    inst.status
                );
                // Remove the dead instance so its port can be reused.
                let _ = store::delete_instance(conn, inst).await;
                continue;
            }
            // SELFUP- : a live PID on
            // a row from a PREVIOUS captain (reparented after the supervisor
            // died) is an orphan. Classify by BINARY IDENTITY, not port:
            // binary matches → ADOPT (row kept, port corrected if stale)
            // binary differs → SIGTERM + row cleared (stale row pointing
            // at a process that is provably not this service)
            // Orphan detection: the process's parent must be alive AND this
            // captain's own pid (children of a live captain are ours).
            if pid != 0 && crate::procfs::pid_alive(pid) && pid != std::process::id() {
                let entry = config.catalog.get(&inst.service_type);
                let ours = is_our_child(pid);
                if ours {
                    continue;
                }
                let expected_binary = expected_binary_for(&inst.service_type, entry);
                if !is_expected_binary(pid, &expected_binary) {
                    unsafe { kill_signal(pid, 15) };
                    let _ = store::mark_killed(conn, inst).await;
                    let _ = store::delete_instance(conn, inst).await;
                    tracing::warn!(
                        service = %inst.service_type,
                        pid,
                        expected = %expected_binary,
                        "boot sweep: orphaned process runs a different binary than expected — \
                         SIGTERM sent, registry row cleared"
                    );
                    continue;
                }
                // Adopt: correct the row's port to the AUTHORITY port
                // when one exists (DUPROW-1 seam 5, DESIGN §5.10.2 —
                // the port-25 trap). Rule order:
                // (a) catalog `fixed_port` + the process holds it →
                //     re-key to the fixed port (the declared health
                //     surface — a row parked on a protocol port like
                //     gate's SMTP 25 gets healed to 8103);
                // (b) recorded port + the process holds it → TRUST the
                //     recorded port (multi-listener services must not
                //     be re-keyed to their LOWEST listener);
                // (c) neither → lowest-listener fallback (stale rows
                //     from prior rolling upgrades).
                let entry_ref = config.catalog.get(&inst.service_type);
                let mut actual_port = inst.local_port;
                if let Some(fixed) = entry_ref.and_then(|e| {
                    let fp = e.fixed_port;
                    (fp > 0).then_some(fp)
                }) {
                    let holder = pid_on_port(fixed);
                    if holder == Some(pid) {
                        actual_port = fixed;
                    }
                }
                if actual_port == inst.local_port {
                    let recorded_port_serves = server_pid_on_port_or_expected(
                        inst.local_port,
                        &expected_binary,
                        pid,
                    );
                    if !recorded_port_serves {
                        actual_port = listen_port_of(pid).unwrap_or(inst.local_port);
                    }
                }
                if actual_port != inst.local_port {
                    let mut corrected = inst.clone();
                    corrected.local_port = actual_port;
                    corrected.key = store::ServiceInstance::make_key(
                        &inst.service_type,
                        &config.local_ip,
                        actual_port,
                    );
                    let _ = store::delete_instance(conn, inst).await;
                    let _ = store::upsert_instance(conn, &corrected).await;
                    tracing::info!(
                        service = %inst.service_type,
                        pid,
                        old_port = inst.local_port,
                        port = actual_port,
                        "boot sweep: adopted orphaned service — registry port corrected"
                    );
                    adopted.insert(
                        inst.service_type.clone(),
                        AdoptedInstance {
                            local_port: actual_port,
                            pid,
                        },
                    );
                } else {
                    tracing::info!(
                        service = %inst.service_type,
                        pid,
                        port = inst.local_port,
                        "boot sweep: adopted orphaned service on its expected port"
                    );
                    adopted.insert(
                        inst.service_type.clone(),
                        AdoptedInstance {
                            local_port: inst.local_port,
                            pid,
                        },
                    );
                }
            }
        }
    }
    Ok(adopted)
}

/// Is `pid` a direct child of THIS captain process? Orphans from a dead
/// captain are reparented (PPID = 1 or another ancestor), so a live PPID
/// mismatch identifies them. Best-effort — a read failure conservatively
/// reports "ours" (never kills a process we can't classify).
fn is_our_child(pid: u32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => {
            // The comm field can contain spaces — parse after the last ')'.
            match stat.rsplit_once(')') {
                Some((_comm, _rest)) => {
                    let mut fields =
                        stat[stat.find(") ").map(|i| i + 2).unwrap_or(0)..].split_whitespace();
                    // fields: state(1) ppid(2) — offset after state.
                    let _state = fields.next();
                    fields
                        .next()
                        .and_then(|ppid| ppid.parse::<u32>().ok())
                        .map(|ppid| ppid == std::process::id())
                        .unwrap_or(true)
                }
                None => true,
            }
        }
        Err(_) => true,
    }
}

/// Check if a TCP port is already in use. (Public — the scaler also uses
/// this to find a free port when scaling up.)
/// Handle is port in use.
pub fn is_port_in_use(port: u16) -> bool {
    // Check on.0 (all interfaces) since services bind on all
    // interfaces — a port taken on any interface is unavailable.
    std::net::TcpListener::bind(("0.0.0.0", port)).is_err()
}

extern "C" {
    fn kill(pid: u32, sig: i32) -> i32;
}

/// Send a signal to a process (POSIX `kill`).
unsafe fn kill_signal(pid: u32, sig: i32) -> i32 {
    kill(pid, sig)
}

/// Find the PID of the process listening on a TCP port (Linux only).
/// Returns `None` on non-Linux or if no listener is found.
pub(crate) fn pid_on_port(port: u16) -> Option<u32> {
    // Use lsof to find the listener PID. This is more portable than
    // parsing /proc/net/tcp.
    let output = std::process::Command::new("lsof")
        .args(["-ti", &format!(":{port}"), "-sTCP:LISTEN"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pid_str = stdout.trim().lines().next()?;
    pid_str.parse::<u32>().ok()
}

/// DUPROW-1 seam 5 helper (DESIGN §5.10.2): does the recorded port hold
/// a listener owned by THIS process (pid) running the expected binary?
/// A `true` result means the recorded port is one of the process's own
/// listeners — the boot sweep must NOT re-key the row away from it.
pub(crate) fn server_pid_on_port_or_expected(
    port: u16,
    expected_binary: &str,
    pid: u32,
) -> bool {
    match pid_on_port(port) {
        Some(holder) => holder == pid && is_expected_binary(holder, expected_binary),
        None => false,
    }
}

/// DUPROW-1 (DESIGN §5.10.2, "check the live process, not just the row"):
/// locate a LIVE, row-less process serving `service_type` by scanning the
/// port range for a listener whose binary identity matches the type's
/// expected binary. Used by the last-resort respawner when the registry
/// shows no live row: a row-less live process is ADOPTED (row re-created)
/// instead of duplicated by a fresh spawn. The scan is bounded by the
/// port range and each probe is a single `lsof` call — it runs at most
/// once per `last_resort_respawn_s` per alerted service.
pub(crate) fn find_rowless_live_service(
    _service_type: &str,
    expected_binary: &str,
    port_range: (u16, u16),
) -> Option<(u16, u32)> {
    for port in port_range.0..=port_range.1 {
        if let Some(pid) = pid_on_port(port) {
            if is_expected_binary(pid, expected_binary) {
                return Some((port, pid));
            }
        }
    }
    None
}

/// Check if a PID's process name matches the expected binary name (multi-strategy):
/// comm, /proc/{pid}/exe symlink target, and the full cmdline (covers cargo-run
/// wrappers and >15-char comm truncation).
pub(crate) fn is_expected_binary(pid: u32, expected_binary: &str) -> bool {
    #[cfg(target_os = "linux")]
    {
        // /proc/<pid>/comm contains the process name (max 15 chars).
        // For "sentin8-bff" (binary name) this is the 11-char comm
        // comm truncates to 15 chars ("sentin8-bff-ser" or similar),
        // so we also fall back to the full cmdline check below.
        if let Ok(comm) = std::fs::read_to_string(format!("/proc/{pid}/comm")) {
            let comm = comm.trim();
            // The comm field is the binary name. For cargo-run processes,
            // the comm might be "cargo" (not the service binary). Check
            // both the comm and the full cmdline for the binary name.
            if comm == expected_binary {
                return true;
            }
            // Also check /proc/<pid>/cmdline for cargo-run'd processes
            // (the binary name appears in the cargo args).
            if let Ok(cmdline) = std::fs::read_to_string(format!("/proc/{pid}/cmdline")) {
                // cmdline is null-separated; replace with spaces for matching.
                let cmdline = cmdline.replace('\0', " ");
                if cmdline.contains(expected_binary) {
                    return true;
                }
            }
        }
        false
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pid, expected_binary);
        false
    }
}
