// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Axum handlers for the Captain management API.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use axum::extract::{Path, Query, State};
use axum::response::IntoResponse;
use axum::Json;
use serde::Deserialize;
use tokio::sync::watch;

use crate::catalog::ServiceCatalogEntry;
use crate::config::CaptainConfig;
use crate::store;

#[derive(Clone)]
/// app state.
pub struct AppState {
    /// The config.
    pub config: Arc<CaptainConfig>,
    /// Shield engine (Phase - ): step 5 gates every
    /// control endpoint. Captain has no tenant realm of its own - the
    /// scope-mirror permit is platform-admin keyed.
    /// The policy.
    pub policy: std::sync::Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface.
    /// The admin.
    pub admin: sentin8::shield::admin::SharedAdminState,
    /// Hot-reloadable service catalog - can be updated at runtime via
    /// `POST /v1/captain/add-catalog` without restarting captain.
    /// Initialized from `config.catalog` at startup; new entries are
    /// merged in via `add_catalog`.
    /// The live catalog.
    pub live_catalog: Arc<RwLock<HashMap<String, ServiceCatalogEntry>>>,
    /// The conn.
    pub conn: glide::GlideClient,
    /// The shutdown tx.
    pub shutdown_tx: watch::Sender<bool>,
    /// The resolved boot allow-list (READYSCOPE-1): the SAME set the boot
    /// spawn loop filters with - `Some(set)` for a scoped boot
    /// (`SENTIN8_SERVICES` enumerated, or the unset platform-only
    /// default), `None` for a full-fleet boot (`SENTIN8_SERVICES=all`).
    /// Readiness accounting (startup-stream totals) rides this set - the
    /// scoped stream reports the scoped types' denominator and completes
    /// with them, instead of counting never-spawned verticals as pending
    /// against the catalog union.
    pub boot_allow: Option<std::collections::HashSet<String>>,
}

/// Step 5 - Shield decides. Captain's control endpoints are
/// platform-operations surfaces: the enforced scope-mirror permit keys on
/// `sentin8:captain:admin` (granted to platform admins via the sys role
/// nesting). No token → 401; deny → 403.
///
/// Local control channel : a request carrying
/// `x-sentin8-local-peer-uid` arrived over the Unix domain socket, where
/// the accept loop injected the kernel-proven `SO_PEERCRED` uid ONLY after
/// confirming root or socket-owner (unauthorized peers never reach the
/// router; the TCP listener strips client-supplied copies). Presence of
/// the header therefore *is* the authorization - no Bearer token needed.
///
/// `pub(crate)` so the admin-UI surface (`crate::admin_ui`) reuses the same
/// gate - the RFW pages expose the same approve action the HTTP API does
/// and must not be a weaker path.
pub(crate) async fn require_captain_policy(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(), (axum::http::StatusCode, String)> {
    if let Some(uid) = headers
        .get(crate::local::LOCAL_PEER_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u32>().ok())
    {
        tracing::info!(
            uds_peer_uid = uid,
            "captain management request authorized via local control socket"
        );
        return Ok(());
    }
    let a = sentin8::auth::client::verify_bearer_token(&state.admin.auth_client, headers)
        .await
        .map_err(|(s, m)| (s, format!("captain: {m}")))?;
    crate::policy::require_policy(
        &state.policy,
        &a,
        headers,
        sentin8::shield::EvalTarget::new("sentin8:captain:admin"),
    )
    .await?;
    Ok(())
}

/// Step 5 for the remote-spawn surface (FLEET-4, DESIGN §11.4) - the same
/// 8-step pipeline, a DIFFERENT action: the M2M `captain-remote` workload
/// presents the granular `sentin8:captain:instances:write` scope, so the
/// Shield evaluation targets that action, not the operator
/// `sentin8:captain:admin` one. The operator path (a human bearer with the
/// admin scope) is also admitted - the CLI uses it to place services by
/// hand. No token → 401; neither scope → 403.
pub(crate) async fn require_instances_write(
    state: &AppState,
    headers: &axum::http::HeaderMap,
) -> Result<(), (axum::http::StatusCode, String)> {
    let a = sentin8::auth::client::verify_bearer_token(&state.admin.auth_client, headers)
        .await
        .map_err(|(s, m)| (s, format!("captain: {m}")))?;
    let ok = crate::policy::require_policy(
        &state.policy,
        &a,
        headers,
        sentin8::shield::EvalTarget::new("sentin8:captain:instances:write"),
    )
    .await;
    match ok {
        // The granular remote-spawn scope admitted the call.
        Ok(_) => Ok(()),
        // 403 on the granular action: the caller may still hold the
        // operator admin scope (a human placing services) - retry the
        // standard gate before refusing.
        Err(err @ (axum::http::StatusCode::FORBIDDEN, _)) => {
            if a.has_scope("sentin8:captain:admin") {
                Ok(())
            } else {
                Err(err)
            }
        }
        Err(e) => Err(e),
    }
}

#[derive(Debug, Deserialize)]
/// The listquery type.
pub struct ListQuery {
    /// The service type.
    pub service_type: Option<String>,
    /// The local ip.
    pub local_ip: Option<String>,
    /// The status.
    pub status: Option<String>,
}

/// Handle health.
pub async fn health(State(_state): State<AppState>) -> Json<serde_json::Value> {
    Json(
        serde_json::json!({"status": "ok", "service": "sentin8:captain", "version": sentin8::build_info::id(), "build": sentin8::build_info::build_hash()}),
    )
}

/// POST /v1/captain/shutdown - trigger a full graceful shutdown.
/// Stops all managed services, releases the advisory lock, and exits.
/// This is the proper way to bring down the platform (used by `sentin8 captain stop`).
/// Handle shutdown.
pub async fn shutdown(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    if let Err((status, msg)) = require_captain_policy(&state, &headers).await {
        // Return the REAL HTTP status - embedding the auth error in a 200
        // body makes `sentin8 captain stop` treat the rejection as success and
        // hang forever waiting for a shutdown that never happened.
        return Err((status, msg));
    }

    tracing::info!("shutdown requested via HTTP API - initiating graceful shutdown");
    let _ = state.shutdown_tx.send(true);
    Ok(Json(serde_json::json!({"status": "shutting_down"})))
}

/// GET /v1/captain/upgrade-status/{key} - poll the phase of a rolling upgrade.
/// Returns the current phase, or 404 if no upgrade is in progress.
/// Handle upgrade status.
pub async fn upgrade_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    require_captain_policy(&state, &headers).await?;

    let upgrade_key = format!("captain:upgrade:{}", key);
    let conn = state.conn.clone();
    let val: Option<String> = glide::cmd("GET")
        .arg(&upgrade_key)
        .query_async(&conn)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    match val {
        Some(json) => {
            let parsed: serde_json::Value =
                serde_json::from_str(&json).unwrap_or(serde_json::json!({"phase": "unknown"}));
            Ok(Json(parsed))
        }
        None => Err((
            axum::http::StatusCode::NOT_FOUND,
            "no upgrade in progress for this key".into(),
        )),
    }
}

/// GET /v1/captain/upgrade-stream/{key} - SSE stream of upgrade progress.
/// Polls Valkey every 2s and streams each phase update as an SSE event.
/// Closes when the upgrade reaches a terminal phase (complete, aborted, rolled_back)
/// or after 10 minutes with no update.
///
/// Shield-gated like every management surface - the gate runs before the
/// stream opens, so a rejected request never holds a stream.
/// Handle upgrade stream.
pub async fn upgrade_stream(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    require_captain_policy(&state, &headers).await?;

    let upgrade_key = format!("captain:upgrade:{}", key);
    let stream = async_stream::stream! {
           let conn = state.conn.clone();
           let mut last_payload: Option<String> = None;
           let mut last_seen = std::time::Instant::now();
           let terminal = ["complete", "aborted", "rolled_back"];

           loop {
               let val: Option<String> = glide::cmd("GET")
                   .arg(&upgrade_key)
                   .query_async(&conn)
                   .await
                   .ok()
                   .flatten();

               match val {
                   Some(payload) => {
                       last_seen = std::time::Instant::now();
                       if Some(&payload) != last_payload.as_ref() {
                           last_payload = Some(payload.clone());
                           let parsed: serde_json::Value =
                               serde_json::from_str(&payload).unwrap_or(serde_json::json!({"phase": "unknown"}));
                           let phase = parsed.get("phase").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                           yield Ok::<_, std::convert::Infallible>(
                               axum::response::sse::Event::default()
                                   .event("progress")
                                   .json_data(&parsed)
                                   .unwrap_or(axum::response::sse::Event::default().data(payload.clone())),
                           );
                           if terminal.contains(&phase.as_str()) {
                               yield Ok(axum::response::sse::Event::default().event("done").data("[done]"));
                               break;
                           }
                       }
                   }
                   None => {
    // Key expired or not yet written - if we never saw data and 30s passed, 404.
                       if last_payload.is_none() && last_seen.elapsed().as_secs() > 30 {
                           yield Ok(axum::response::sse::Event::default()
                               .event("error")
                               .data("no upgrade found for this key"));
                           break;
                       }
    // If we saw data before but it expired (10min TTL), the upgrade is done.
                       if last_payload.is_some() && last_seen.elapsed().as_secs() > 30 {
                           yield Ok(axum::response::sse::Event::default()
                               .event("done")
                               .data("[expired]"));
                           break;
                       }
                   }
               }
               tokio::time::sleep(std::time::Duration::from_secs(2)).await;
           }
       };

    Ok(axum::response::sse::Sse::new(stream))
}

/// GET /v1/captain/startup-stream - SSE stream of startup progress.
///
/// Polls the service registry every 2s and streams readiness updates:
/// - event "progress": `{"ready_count": N, "total": M, "pending": [...], "alerts": [...]}`
/// - event "alert": one per crash-looped service (give-up after max restarts)
/// - event "ready": `{"ready_count": M, "total": M}` (all services Active)
/// - event "done": `[done]` (stream closes after ready)
///
/// Closes when all boot-scoped services have enough Active instances, or
/// after 5 minutes with no progress. The accounting set is the EFFECTIVE
/// BOOT SET (READYSCOPE-1): the resolved `SENTIN8_SERVICES` allow-list
/// when the boot was scoped, the full catalog union otherwise - a
/// platform-only boot reports `⏳ 18/19` and completes `ready` when the
/// platform types are Active, rather than waiting forever on 48
/// deliberately-not-spawned vertical types.
///
/// Shield-gated like every management surface - the gate runs before the
/// stream opens, so a rejected request never holds a stream. Note the CLI
/// (`stream_startup`, invoked right after spawning captain) calls this
/// best-effort: without an operator token it prints a hint and moves on;
/// `make status` remains the authoritative readiness check.
///
/// The accounting set as a pure function (unit-testable without Valkey):
/// scoped boot → the allow-list ∩ catalog entry types; unscoped → the
/// full catalog.
fn readiness_accounting_types(
    boot_allow: Option<&std::collections::HashSet<String>>,
    catalog: &HashMap<String, ServiceCatalogEntry>,
) -> Vec<String> {
    match boot_allow {
        Some(allow) => catalog
            .keys()
            .filter(|t| allow.contains(*t))
            .cloned()
            .collect::<Vec<String>>(),
        None => catalog.keys().cloned().collect(),
    }
}

/// Compute the pending list + counts over an accounting set (READYSCOPE-1
/// pure helper): a type is pending when fewer than `MIN_INSTANCES`
/// instances are Active.
fn readiness_accounting(
    accounting_types: &[String],
    active_counts: &HashMap<String, usize>,
    instances: &[store::ServiceInstance],
) -> (usize, Vec<serde_json::Value>) {
    let mut pending: Vec<serde_json::Value> = Vec::new();
    for service_type in accounting_types {
        let active = *active_counts.get(service_type).unwrap_or(&0);
        if active < crate::catalog::MIN_INSTANCES as usize {
            let status = instances
                .iter()
                .find(|i| &i.service_type == service_type)
                .map(|i| i.status.as_str())
                .unwrap_or("missing");
            pending.push(serde_json::json!({
                "service": service_type,
                "active": active,
                "required": crate::catalog::MIN_INSTANCES,
                "status": status,
            }));
        }
    }
    (accounting_types.len() - pending.len(), pending)
}

/// Stream readiness progress until the boot-scoped service set is Active.
///
/// The accounting set is the effective boot scope (READYSCOPE-1) - see the
/// module-level doc on [`readiness_accounting_types`].
pub async fn startup_stream(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    require_captain_policy(&state, &headers).await?;

    let stream = async_stream::stream! {
               let conn = state.conn.clone();
               // READYSCOPE-1: the accounting set is the effective boot
               // scope, NOT the catalog union. The union stays the live
               // catalog (start-services/remote spawn can name any type);
               // this stream only reports types the boot was asked to run.
               let accounting_types: Vec<String> = {
                   let catalog = state.live_catalog.read().unwrap();
                   readiness_accounting_types(state.boot_allow.as_ref(), &catalog)
               };
               let total = accounting_types.len();
               let mut last_ready_count = 0usize;
               let mut last_progress = std::time::Instant::now();

               loop {
                   let instances = store::list_all(&conn).await.unwrap_or_default();

        // Count Active instances per service type.
                   use std::collections::HashMap;
                   let active_counts: HashMap<String, usize> = instances
                       .iter()
                       .filter(|i| i.status == "Active")
                       .fold(HashMap::new(), |mut acc, i| {
                           *acc.entry(i.service_type.clone()).or_insert(0) += 1;
                           acc
                       });

        // Check which services are pending (scoped accounting only).
                   let (ready_count, pending) = readiness_accounting(&accounting_types, &active_counts, &instances);
                   let ready = pending.is_empty();

    // WARN-10: crash-looped services surface as FIRST-CLASS alerts - the
    // CLI prints them and the operator sees WHICH service gave up and where
    // to look, instead of a silent 'waiting on' loop that ends in timeout.
                   let alerts = store::list_alerts(&conn).await.unwrap_or_default();
                   let alert_values: Vec<serde_json::Value> = alerts
                       .iter()
                       .map(|(svc, a)| {
                           serde_json::json!({
                               "service": svc,
                               "restarts": a.restarts,
                               "reason": a.reason,
                               "log_path": a.log_path,
                           })
                       })
                       .collect();
                   let mut reported_alerts: std::collections::HashSet<String> =
                       std::collections::HashSet::new();

    // Only emit when the count changes (avoid spamming identical events).
                   if ready_count != last_ready_count || ready {
                       last_ready_count = ready_count;
                       last_progress = std::time::Instant::now();

                       let payload = serde_json::json!({
                           "ready_count": ready_count,
                           "total": total,
                           "pending": pending,
                           "alerts": alert_values,
                       });

    // One alert event per NOT-YET-REPORTED failure (the CLI prints once per
    // give-up; later progress frames re-carry the array for late joiners).
                       for (svc, a) in alerts.iter() {
                           if reported_alerts.insert(svc.clone()) {
                               yield Ok::<_, std::convert::Infallible>(
                                   axum::response::sse::Event::default()
                                       .event("alert")
                                       .json_data(serde_json::json!({
                                           "service": svc,
                                           "restarts": a.restarts,
                                           "reason": a.reason,
                                           "log_path": a.log_path,
                                       }))
                                       .unwrap(),
                               );
                           }
                       }

                       if ready {
                           yield Ok::<_, std::convert::Infallible>(
                               axum::response::sse::Event::default()
                                   .event("ready")
                                   .json_data(&payload)
                                   .unwrap(),
                           );
                           yield Ok(axum::response::sse::Event::default().event("done").data("[done]"));
                           break;
                       } else {
                           yield Ok::<_, std::convert::Infallible>(
                               axum::response::sse::Event::default()
                                   .event("progress")
                                   .json_data(&payload)
                                   .unwrap(),
                           );
                       }
                   }

        // Timeout: 5 minutes with no progress.
                   if last_progress.elapsed().as_secs() > 300 {
                       yield Ok::<_, std::convert::Infallible>(
                           axum::response::sse::Event::default()
                               .event("timeout")
                               .data("startup stalled - no progress for 5 minutes"),
                       );
                       break;
                   }

                   tokio::time::sleep(std::time::Duration::from_secs(2)).await;
               }
           };

    Ok(axum::response::sse::Sse::new(stream))
}

/// GET /v1/captain/shutdown-stream - SSE stream of shutdown progress.
///
/// Polls the service registry every 2s and streams the number of
/// remaining Active/Starting/Stopping instances until all are
/// Stopped/Killed (shutdown complete).
///
/// - event "progress": `{"remaining": N, "total": M, "stopped": [...]`
/// - event "done": `[done]` (all stopped)
/// - event "timeout": stream closes after 2 minutes
///
/// Shield-gated like every management surface - the gate runs before the
/// stream opens. The CLI consumes this best-effort and has its own
/// SIGKILL deadline, so a rejection degrades to a missing progress feed,
/// not a broken shutdown.
/// Handle shutdown stream.
pub async fn shutdown_stream(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    require_captain_policy(&state, &headers).await?;

    let stream = async_stream::stream! {
           let conn = state.conn.clone();
           let mut last_remaining = usize::MAX;
           let start = std::time::Instant::now();

           loop {
               let instances = store::list_all(&conn).await.unwrap_or_default();

    // Count instances that are not yet fully stopped.
               let live: Vec<_> = instances
                   .iter()
                   .filter(|i| {
                       i.service_type != "sentin8:captain"
                           && (i.status == "Active"
                               || i.status == "Starting"
                               || i.status == "Started"
                               || i.status == "Inactive"
                               || i.status == "Stopping")
                   })
                   .collect();

               let remaining = live.len();
               let total = instances.iter().filter(|i| i.service_type != "sentin8:captain").count();

               if remaining != last_remaining {
                   last_remaining = remaining;
                   let stopped_names: Vec<String> = instances
                       .iter()
                       .filter(|i| {
                           i.service_type != "sentin8:captain"
                               && (i.status == "Stopped" || i.status == "Killed")
                       })
                       .map(|i| i.service_type.clone())
                       .collect();

                   let payload = serde_json::json!({
                       "remaining": remaining,
                       "total": total,
                       "stopped": stopped_names,
                   });

                   if remaining == 0 {
                       yield Ok::<_, std::convert::Infallible>(
                           axum::response::sse::Event::default()
                               .event("done")
                               .json_data(&payload)
                               .unwrap(),
                       );
                       break;
                   } else {
                       yield Ok::<_, std::convert::Infallible>(
                           axum::response::sse::Event::default()
                               .event("progress")
                               .json_data(&payload)
                               .unwrap(),
                       );
                   }
               }

    // Timeout: 2 minutes.
               if start.elapsed().as_secs() > 120 {
                   yield Ok::<_, std::convert::Infallible>(
                       axum::response::sse::Event::default()
                           .event("timeout")
                           .data("shutdown timed out - some services did not stop"),
                   );
                   break;
               }

               tokio::time::sleep(std::time::Duration::from_secs(2)).await;
           }
       };

    Ok(axum::response::sse::Sse::new(stream))
}

/// List services.
pub async fn list_services(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(q): Query<ListQuery>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    require_captain_policy(&state, &headers).await?;

    let conn = state.conn.clone();
    let instances = store::list_all(&conn)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let filtered: Vec<_> = instances
        .into_iter()
        .filter(|i| {
            q.service_type.as_deref().is_none_or(|s| {
                // Accept both colon and legacy hyphen query forms
                // canonicalize before comparing.
                i.service_type == sentin8::config::canonical_service_type(s)
            })
        })
        .filter(|i| q.local_ip.as_deref().is_none_or(|s| i.local_ip == s))
        .filter(|i| q.status.as_deref().is_none_or(|s| i.status == s))
        .collect();
    Ok(Json(filtered))
}

/// GET /v1/captain/machines - returns per-machine host-level CPU% and MEM%
/// from the monitor's periodic `/proc` sampling. One entry per IP.
///
/// Each entry: `{ "ip": "172.x.x.x", "cpu_pct": , "mem_pct": , "used_mb": , "ts": 1692912345 }`
/// List machines.
pub async fn list_machines(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    require_captain_policy(&state, &headers).await?;

    let conn = state.conn.clone();
    // Scan all captain:host:* keys.
    let keys: Vec<String> = glide::cmd("KEYS")
        .arg("captain:host:*")
        .query_async(&conn)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut machines = Vec::new();
    for key in &keys {
        let val: String = match glide::cmd("GET").arg(key).query_async(&conn).await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&val).unwrap_or(serde_json::Value::Null);
        let ip = key.strip_prefix("captain:host:").unwrap_or("").to_string();
        machines.push(serde_json::json!({
            "ip": ip,
            "cpu_pct": parsed.get("cpu_pct").and_then(|v| v.as_f64()).unwrap_or(0.0),
            "mem_pct": parsed.get("mem_pct").and_then(|v| v.as_f64()).unwrap_or(0.0),
            "used_mb": parsed.get("used_mb").and_then(|v| v.as_f64()).unwrap_or(0.0),
            "ts": parsed.get("ts").and_then(|v| v.as_i64()).unwrap_or(0),
 // Saturation annotation (PROVISION-1, design ) - read by
 // the autoscaler role and surfaced to operators here.
            "saturated": parsed.get("saturated").and_then(|v| v.as_bool()).unwrap_or(false),
            "saturated_service": parsed.get("saturated_service").and_then(|v| v.as_str()).unwrap_or(""),
        }));
    }
    machines.sort_by(|a, b| {
        a.get("ip")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .cmp(b.get("ip").and_then(|v| v.as_str()).unwrap_or(""))
    });
    Ok(Json(machines))
}

/// Fetch service.
pub async fn get_service(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    require_captain_policy(&state, &headers).await?;

    let conn = state.conn.clone();
    let inst = resolve_instance(&conn, &key)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let inst = match inst {
        KeyResolution::Unique(i) => i,
        KeyResolution::NotFound(m) => {
            return Err((axum::http::StatusCode::NOT_FOUND, m));
        }
        KeyResolution::Ambiguous(m) => {
            return Err((axum::http::StatusCode::CONFLICT, m));
        }
    };
    Ok(Json(inst))
}

/// Request body for action.
#[derive(Debug, Deserialize)]
pub struct ActionRequest {
    /// The action: `restart`, `stop`, or `start`.
    pub action: String, // "restart" | "stop" | "start"
}

/// Handle service action.
pub async fn service_action(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Path(key): Path<String>,
    Json(req): Json<ActionRequest>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    require_captain_policy(&state, &headers).await?;

    let conn = state.conn.clone();
    let inst = resolve_instance(&conn, &key)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let inst = match inst {
        KeyResolution::Unique(i) => i,
        KeyResolution::NotFound(m) => {
            return Err((axum::http::StatusCode::NOT_FOUND, m));
        }
        KeyResolution::Ambiguous(m) => {
            return Err((axum::http::StatusCode::CONFLICT, m));
        }
    };
    // SELFUP- : EVERY
    // per-instance action on the captain row targets the supervisor itself.
    // `restart` SIGTERMs captain's own pid (the control plane died while
    // its children survived reparented) and `stop` would do the same - the
    // monitor loop cannot self-heal a dead supervisor. The supervisor can
    // never replace or terminate its own process; binary updates and
    // control-plane restarts go through `sentin8-cli captain restart`
    // (children keep running and are re-adopted on boot, -2).
    if inst.service_type == "sentin8:captain"
        && matches!(
            req.action.as_str(),
            "upgrade" | "restart" | "stop" | "start"
        )
    {
        return Err((
            axum::http::StatusCode::CONFLICT,
            "cannot target the supervisor itself - captain would kill its own process \
             with no successor (or spawn a second supervisor on the management port). \
             Use `sentin8-cli captain restart` instead."
                .into(),
        ));
    }
    // per-instance actions must resolve
    // the service entry against the LIVE catalog (startup catalog + entries
    // merged at runtime via merge-catalog during vertical enroll), not the
    // startup-only catalog - a vertical's service types are unknown to
    // start_services' live view but missing here otherwise, which made
    // stop/start/upgrade 404 `service not in catalog`. The live catalog is a
    // superset of the startup catalog (merge-catalog only adds/overwrites),
    // so consulting it alone is sufficient.
    let entry = state
        .live_catalog
        .read()
        .unwrap()
        .get(&inst.service_type)
        .cloned()
        .ok_or((
            axum::http::StatusCode::NOT_FOUND,
            "service not in catalog".into(),
        ))?;
    match req.action.as_str() {
        "restart" => {
            let pid = inst.pid;
            if pid != 0 {
                // Kill the existing process (the monitor loop will self-heal).
                let _ = unsafe { kill_signal(pid, 15) };
            }
            Ok(Json(serde_json::json!({"action": "restart", "key": key})))
        }
        "stop" => {
            let pid = inst.pid;
            if pid != 0 {
                let _ = crate::supervisor::stop(
                    &state.conn.clone(),
                    &inst,
                    &entry,
                    pid,
                    crate::catalog::GRACE_PERIOD_S,
                    state.config.upgrade_drain_s,
                )
                .await;
            }
            Ok(Json(serde_json::json!({"action": "stop", "key": key})))
        }
        "start" => {
            // Spawn on the existing instance's port. Same-key respawn: the
            // prior row's restart count carries over (captain DESIGN §8
            // invariant 10) - a manual start after kills must not reset the
            // consecutive-restart bookkeeping.
            let _ = crate::supervisor::spawn(
                &state.conn.clone(),
                &inst,
                &entry,
                inst.local_port,
                Some(inst.restarts),
            )
            .await
            .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            Ok(Json(serde_json::json!({"action": "start", "key": key})))
        }
        "upgrade" => {
            // Rolling upgrade (zero-downtime with rollback) - runs in a
            // background task so the API returns immediately and captain
            // can continue serving other requests. (The captain-key case
            // is refused above - SELFUP-1.1/1.3.)
            let conn = state.conn.clone();
            let config = state.config.clone();
            let inst = inst.clone();
            let entry = entry.clone();
            let upgrade_key = format!("captain:upgrade:{}", inst.key);

            // Write initial progress to Valkey.
            let _: () = glide::cmd("SETEX")
                .arg(&upgrade_key)
                .arg(600) // 10min TTL
                .arg(
                    serde_json::to_string(&serde_json::json!({
                        "phase": "starting",
                        "service": inst.service_type,
                        "old_port": inst.local_port,
                    }))
                    .unwrap_or_default(),
                )
                .query_async(&state.conn.clone())
                .await
                .unwrap_or(());

            // Spawn the upgrade as a background task.
            tokio::spawn(async move {
                run_upgrade(conn, &config, &inst, &entry, upgrade_key).await;
            });

            Ok(Json(serde_json::json!({
                "action": "upgrade",
                "key": key,
                "status": "initiated",
            })))
        }

        other => Err((
            axum::http::StatusCode::BAD_REQUEST,
            format!("unknown action: {other}"),
        )),
    }
}

/// Background upgrade task - runs the full rolling upgrade flow
/// without blocking the API. Captain continues serving requests normally.
async fn run_upgrade(
    conn: glide::GlideClient,
    config: &crate::config::CaptainConfig,
    inst: &store::ServiceInstance,
    entry: &crate::catalog::ServiceCatalogEntry,
    upgrade_key: String,
) {
    let service_type = inst.service_type.clone();
    let old_port = inst.local_port;
    let local_ip = inst.local_ip.clone();

    // Helper: write progress to Valkey under BOTH the request key (the OLD
    // instance's `{ip}:{port}`) and the NEW instance's key
    // (`captain:upgrade:new:{ip}:{new_port}`) - the monitor's self-heal guard
    // `is_upgrade_in_progress` checks the key of whichever row it samples,
    // so publishing under both identities is what shields the flapping new
    // instance for the whole run (captain DESIGN §8 invariant 9). Keys
    // expire with the 10-min TTL; on terminal phases they are deleted.
    // The new-instance key is only known after port selection (rolling
    // path) - it is threaded through the calls below via `Some(&nk)`.

    async fn write_progress(
        conn: &glide::GlideClient,
        key: &str,
        phase: &str,
        service_type: &str,
        old_port: u16,
        extra: serde_json::Value,
        new_key: Option<&str>,
    ) {
        let payload = serde_json::to_string(&serde_json::json!({
            "phase": phase,
            "service": service_type,
            "old_port": old_port,
            "extra": extra,
        }))
        .unwrap_or_default();
        let _: () = glide::cmd("SETEX")
            .arg(key)
            .arg(600)
            .arg(&payload)
            .query_async(conn)
            .await
            .unwrap_or(());
        if let Some(nk) = new_key {
            let nk = format!("captain:upgrade:{nk}");
            let _: () = glide::cmd("SETEX")
                .arg(nk)
                .arg(600)
                .arg(&payload)
                .query_async(conn)
                .await
                .unwrap_or(());
        }
    }

    // Helper: delete BOTH progress keys. Terminal phases (aborted /
    // rolled_back / complete) must clear the guard IMMEDIATELY: a monitor
    // health-kill AFTER a finished run (or an abort's row delete) must
    // never be blocked by keys that would otherwise ride the 10-min TTL -
    // a latched guard left the fleet unhealed for the whole TTL window
    // (captain DESIGN §8 invariant 9: the guard covers the RUN, not the
    // run plus ten minutes). The SSE/CLI still read the terminal phase
    // from the written payload (2s polls) before the delete lands.
    async fn clear_progress(conn: &glide::GlideClient, key: &str, new_key: Option<&str>) {
        let _: Result<i64, glide::GlideError> = glide::cmd("DEL").arg(key).query_async(conn).await;
        if let Some(nk) = new_key {
            let _: Result<i64, glide::GlideError> = glide::cmd("DEL")
                .arg(format!("captain:upgrade:{nk}"))
                .query_async(conn)
                .await;
        }
    }

    // ── Fixed-port services (e.g. proxy on 443, log on 8001) ──────────
    // A rolling upgrade (spawn new on a free port, drain old) doesn't work
    // for fixed-port services - clients expect them on the well-known port.
    // Instead: stop the old instance first, then spawn the new one on the
    // same fixed port and wait for it to become Active. This is a brief
    // downtime (a few seconds) but is the only correct approach for a
    // service that must listen on a specific port.
    if entry.fixed_port > 0 || entry.upgrade_stop_first {
        tracing::info!(service = %service_type, port = old_port, "upgrade: stop-first service - stopping old instance first");

        // 1. Stop the old instance.
        let old_pid = inst.pid;
        if old_pid != 0 {
            let _ = crate::supervisor::stop(
                &conn,
                inst,
                entry,
                old_pid,
                crate::catalog::GRACE_PERIOD_S,
                config.upgrade_drain_s,
            )
            .await;
            tracing::info!(service = %service_type, port = old_port, "upgrade: old instance stopped");
        }
        write_progress(
            &conn,
            &upgrade_key,
            "stopped_old",
            &service_type,
            old_port,
            serde_json::json!({}),
            None,
        )
        .await;

        // 2. Spawn the new instance on the same fixed port.
        write_progress(
            &conn,
            &upgrade_key,
            "starting",
            &service_type,
            old_port,
            serde_json::json!({}),
            None,
        )
        .await;
        let new_pid = match crate::supervisor::spawn(&conn, inst, entry, old_port, None).await {
            Ok(pid) => pid,
            Err(e) => {
                tracing::error!(service = %service_type, error = %e, "upgrade: failed to spawn new instance - aborting");
                write_progress(
                    &conn,
                    &upgrade_key,
                    "aborted",
                    &service_type,
                    old_port,
                    serde_json::json!({"reason": "spawn failed"}),
                    None,
                )
                .await;
                return;
            }
        };
        tracing::info!(service = %service_type, port = old_port, new_pid, "upgrade: new instance spawned on fixed port");
        write_progress(
            &conn,
            &upgrade_key,
            "spawned",
            &service_type,
            old_port,
            serde_json::json!({"new_port": old_port, "new_pid": new_pid}),
            None,
        )
        .await;

        // 3. Wait for Active (up to 120s).
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
        let mut new_active = false;
        while std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            let instances = store::list_for_ip(&conn, &local_ip)
                .await
                .unwrap_or_default();
            if let Some(new_inst) = instances
                .iter()
                .find(|i| i.local_port == old_port && i.pid == new_pid)
            {
                if new_inst.status == "Active" {
                    new_active = true;
                    tracing::info!(service = %service_type, port = old_port, "upgrade: new instance is Active");
                    break;
                }
            }
        }

        if !new_active {
            tracing::warn!(service = %service_type, port = old_port, "upgrade: did not become Active - aborting");
            write_progress(
                &conn,
                &upgrade_key,
                "aborted",
                &service_type,
                old_port,
                serde_json::json!({"reason": "did not become Active"}),
                None,
            )
            .await;
            return;
        }
        write_progress(
            &conn,
            &upgrade_key,
            "active",
            &service_type,
            old_port,
            serde_json::json!({"new_port": old_port}),
            None,
        )
        .await;

        // 4. Wait for stability (60s).
        let stability_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut last_restarts = -1i32;
        let mut stable = false;
        while std::time::Instant::now() < stability_deadline {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let instances = store::list_for_ip(&conn, &local_ip)
                .await
                .unwrap_or_default();
            if let Some(new_inst) = instances
                .iter()
                .find(|i| i.local_port == old_port && i.pid == new_pid)
            {
                if new_inst.status != "Active" {
                    tracing::warn!(service = %service_type, port = old_port, "upgrade: lost Active during stability check - aborting");
                    write_progress(
                        &conn,
                        &upgrade_key,
                        "aborted",
                        &service_type,
                        old_port,
                        serde_json::json!({"reason": "lost Active"}),
                        None,
                    )
                    .await;
                    return;
                }
                if last_restarts >= 0 && new_inst.restarts == last_restarts {
                    stable = true;
                    break;
                }
                last_restarts = new_inst.restarts;
            }
        }

        if !stable {
            tracing::warn!(service = %service_type, port = old_port, "upgrade: not stable after 60s - aborting");
            write_progress(
                &conn,
                &upgrade_key,
                "aborted",
                &service_type,
                old_port,
                serde_json::json!({"reason": "not stable"}),
                None,
            )
            .await;
            return;
        }

        tracing::info!(service = %service_type, port = old_port, "upgrade: complete");
        write_progress(
            &conn,
            &upgrade_key,
            "complete",
            &service_type,
            old_port,
            serde_json::json!({"new_port": old_port}),
            None,
        )
        .await;
        return;
    }

    // ── Rolling upgrade (non-fixed-port services) ─────────────────
    // 1. Find the next free port and spawn the new instance. The port is
    // RESERVED atomically (UPGRADE-RACE-1) and the reservation is HELD
    // until the new instance reaches Active (captain DESIGN §8
    // invariant 9): releasing at spawn-registration would let a
    // concurrent upgrade's stale registry snapshot + the not-yet-bound
    // port re-acquire the SAME port (both children then die binding it,
    // exactly the 2026-09-29 web/sys/app-on-8021 incident). The 60s
    // TTL is only the crashed-upgrade backstop; on every success or
    // abort path below the reservation is explicitly released.
    let next_port = match crate::scaler::reserve_free_port(&conn, &local_ip, config.port_range)
        .await
    {
        Some(p) => p,
        None => {
            tracing::error!(service = %service_type, "upgrade: no free ports available - aborting");
            return;
        }
    };
    // Fresh instance on a new port: restart count starts at zero (the killed
    // row's count belongs to the OLD instance which stays in place).
    let new_pid = match crate::supervisor::spawn(&conn, inst, entry, next_port, None).await {
        Ok(pid) => pid,
        Err(e) => {
            crate::scaler::release_reserved_port(&conn, &local_ip, next_port).await;
            tracing::error!(service = %service_type, error = %e, "upgrade: failed to spawn new instance - aborting");
            return;
        }
    };
    // Reservation stays HELD here - the registry row alone does not stop a
    // stale parallel scan from re-acquiring the port until the child has
    // actually bound it (captain DESIGN §8 invariant 9). Released after the
    // Active-wait (success) and on every abort path below.
    // The NEW instance's progress key rides the new port - the monitor
    // samples the new row by its own (`{ip}:{port}`) key.
    let new_instance_key = format!("new:{local_ip}:{next_port}");
    tracing::info!(service = %service_type, old_port, new_port = next_port, new_pid, "upgrade: new instance spawned");
    write_progress(
        &conn,
        &upgrade_key,
        "spawned",
        &service_type,
        old_port,
        serde_json::json!({"new_port": next_port, "new_pid": new_pid}),
        Some(&new_instance_key),
    )
    .await;

    // Helper: fetch THE upgraded instance from Valkey. Rows are matched on
    // `service_type` + `local_port` (`+ pid` where the caller has it) -
    // NEVER on port alone: during a botched window several services can
    // hold rows for the same port, and a port-only match polls/deletes
    // another service's instance (captain DESIGN §8 invariant 9).
    async fn get_new_inst(
        conn: &glide::GlideClient,
        local_ip: &str,
        service_type: &str,
        port: u16,
        expected_pid: Option<u32>,
    ) -> Option<store::ServiceInstance> {
        let instances = store::list_for_ip(conn, local_ip).await.ok()?;
        instances.into_iter().find(|i| {
            i.service_type == service_type
                && i.local_port == port
                && expected_pid.is_none_or(|p| i.pid == p)
        })
    }

    // Helper: stop and remove the new instance (abort cleanup). The abort
    // path skips the drain (drain_s = 0) - the new instance never served
    // traffic, so there is nothing to drain.
    async fn stop_new(
        conn: &glide::GlideClient,
        local_ip: &str,
        service_type: &str,
        port: u16,
        expected_pid: Option<u32>,
    ) {
        if let Some(new_inst) = get_new_inst(conn, local_ip, service_type, port, expected_pid).await
        {
            if new_inst.pid != 0 {
                let entry = catalog_entry(&new_inst.service_type);
                let _ = crate::supervisor::stop(conn, &new_inst, &entry, new_inst.pid, 5, 0).await;
            }
            let _ = store::delete_instance(conn, &new_inst).await;
        }
    }

    // Catalog entry fallback for abort cleanup - the upgrade flow knows its
    // entry, but the nested `stop_new` helper is called from branches where
    // only the instance is handy. A default entry (0 offset, HTTPS) matches
    // every normal shell service; gauge-less probing just falls back to the
    // fixed window.
    fn catalog_entry(service_type: &str) -> crate::catalog::ServiceCatalogEntry {
        crate::catalog::ServiceCatalogEntry {
            service_type: service_type.to_string(),
            binary: String::new(),
            binary_path: String::new(),
            start_priority: 0,
            fixed_port: 0,
            health_port: 0,
            use_http_health: false,
            upgrade_stop_first: false,
            extra_env: Default::default(),
            database_env_vars: Vec::new(),
            placement: String::new(),
            singleton: false,
            web_root: String::new(),
        }
    }

    // 2. Wait for the new instance to become Active (poll every 3s, up to 120s).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let mut new_active = false;
    while std::time::Instant::now() < deadline {
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        if let Some(new_inst) =
            get_new_inst(&conn, &local_ip, &service_type, next_port, Some(new_pid)).await
        {
            if new_inst.status == "Active" {
                new_active = true;
                tracing::info!(service = %service_type, new_port = next_port, "upgrade: new instance is Active");
                break;
            }
        }
    }

    if !new_active {
        tracing::warn!(service = %service_type, new_port = next_port, "upgrade: did not become Active - aborting, keeping old instance");
        crate::scaler::release_reserved_port(&conn, &local_ip, next_port).await;
        stop_new(&conn, &local_ip, &service_type, next_port, Some(new_pid)).await;
        write_progress(
            &conn,
            &upgrade_key,
            "aborted",
            &service_type,
            old_port,
            serde_json::json!({"reason": "did not become Active", "new_port": next_port}),
            Some(&new_instance_key),
        )
        .await;
        clear_progress(&conn, &upgrade_key, Some(&new_instance_key)).await;
        return;
    }
    write_progress(
        &conn,
        &upgrade_key,
        "active",
        &service_type,
        old_port,
        serde_json::json!({"new_port": next_port}),
        Some(&new_instance_key),
    )
    .await;
    // The child is Active - its process holds the port; the reservation's
    // job (surviving the unbound window between selection and first bind) is
    // done. Later aborts (stability/rollback) keep the registry row as the
    // port guard for stop_new's own cleanup.
    crate::scaler::release_reserved_port(&conn, &local_ip, next_port).await;
    tracing::info!(
        service = %service_type,
        new_port = next_port,
        "upgrade: port reservation released (child Active, process holds the port)"
    );

    // 3. Wait for stability (no restarts/errors for 60s) - old instance still serving.
    let stability_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut last_restarts = -1i32;
    let mut stable = false;
    while std::time::Instant::now() < stability_deadline {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        if let Some(new_inst) =
            get_new_inst(&conn, &local_ip, &service_type, next_port, Some(new_pid)).await
        {
            if new_inst.status != "Active" {
                tracing::warn!(service = %service_type, new_port = next_port, "upgrade: lost Active during stability check - aborting");
                stop_new(&conn, &local_ip, &service_type, next_port, Some(new_pid)).await;
                write_progress(
                    &conn,
                    &upgrade_key,
                    "aborted",
                    &service_type,
                    old_port,
                    serde_json::json!({"reason": "lost Active during stability check"}),
                    Some(&new_instance_key),
                )
                .await;
                clear_progress(&conn, &upgrade_key, Some(&new_instance_key)).await;
                return;
            }
            if last_restarts >= 0 && new_inst.restarts == last_restarts {
                stable = true;
                break;
            }
            last_restarts = new_inst.restarts;
        }
    }

    if !stable {
        tracing::warn!(service = %service_type, new_port = next_port, "upgrade: not stable after 60s - aborting");
        stop_new(&conn, &local_ip, &service_type, next_port, Some(new_pid)).await;
        write_progress(
            &conn,
            &upgrade_key,
            "aborted",
            &service_type,
            old_port,
            serde_json::json!({"reason": "not stable after 60s"}),
            Some(&new_instance_key),
        )
        .await;
        clear_progress(&conn, &upgrade_key, Some(&new_instance_key)).await;
        return;
    }
    tracing::info!(service = %service_type, new_port = next_port, "upgrade: new instance is stable");
    write_progress(
        &conn,
        &upgrade_key,
        "stable",
        &service_type,
        old_port,
        serde_json::json!({"new_port": next_port}),
        Some(&new_instance_key),
    )
    .await;

    // 4. Mark the old instance as Inactive (drain - stop new traffic).
    let _ = store::mark_inactive(&conn, inst).await;
    tracing::info!(service = %service_type, old_port, "upgrade: old instance set to Inactive (draining)");
    write_progress(
        &conn,
        &upgrade_key,
        "draining",
        &service_type,
        old_port,
        serde_json::json!({"new_port": next_port, "old_port": old_port}),
        Some(&new_instance_key),
    )
    .await;

    // 5. Wait for stability under load (60s) - new instance is now serving all traffic.
    let load_deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let mut last_restarts = -1i32;
    let mut stable_under_load = false;
    while std::time::Instant::now() < load_deadline {
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        if let Some(new_inst) =
            get_new_inst(&conn, &local_ip, &service_type, next_port, Some(new_pid)).await
        {
            if new_inst.status != "Active" {
                tracing::warn!(service = %service_type, new_port = next_port, "upgrade: lost Active under load - rolling back");
                let _ = store::mark_active(&conn, inst).await;
                stop_new(&conn, &local_ip, &service_type, next_port, Some(new_pid)).await;
                tracing::info!(service = %service_type, old_port, "upgrade: old instance reactivated (rollback)");
                write_progress(
                    &conn,
                    &upgrade_key,
                    "rolled_back",
                    &service_type,
                    old_port,
                    serde_json::json!({"reason": "lost Active under load", "new_port": next_port}),
                    Some(&new_instance_key),
                )
                .await;
                clear_progress(&conn, &upgrade_key, Some(&new_instance_key)).await;
                return;
            }
            if last_restarts >= 0 && new_inst.restarts == last_restarts {
                stable_under_load = true;
                break;
            }
            last_restarts = new_inst.restarts;
        }
    }

    if !stable_under_load {
        tracing::warn!(service = %service_type, new_port = next_port, "upgrade: not stable under load - rolling back");
        let _ = store::mark_active(&conn, inst).await;
        stop_new(&conn, &local_ip, &service_type, next_port, Some(new_pid)).await;
        tracing::info!(service = %service_type, old_port, "upgrade: old instance reactivated (rollback)");
        write_progress(
            &conn,
            &upgrade_key,
            "rolled_back",
            &service_type,
            old_port,
            serde_json::json!({"reason": "not stable under load", "new_port": next_port}),
            Some(&new_instance_key),
        )
        .await;
        clear_progress(&conn, &upgrade_key, Some(&new_instance_key)).await;
        return;
    }
    tracing::info!(service = %service_type, new_port = next_port, "upgrade: stable under load");
    write_progress(
        &conn,
        &upgrade_key,
        "stable_under_load",
        &service_type,
        old_port,
        serde_json::json!({"new_port": next_port}),
        Some(&new_instance_key),
    )
    .await;

    // 6. Stop the old instance.
    let old_pid = inst.pid;
    if old_pid != 0 {
        let _ = crate::supervisor::stop(
            &conn,
            inst,
            entry,
            old_pid,
            crate::catalog::GRACE_PERIOD_S,
            config.upgrade_drain_s,
        )
        .await;
        tracing::info!(service = %service_type, old_port, "upgrade: old instance stopped - upgrade complete");
    }

    // 7. Update captain's own env var for this service type so future
    // spawns propagate the new port. Services that use
    // sentin8::service_discovery will pick up the new instance
    // automatically via Valkey pub/sub - no restart needed.
    let port_env = format!("{}_PORT", service_type.to_uppercase());
    if !service_type.contains(':') {
        std::env::set_var(&port_env, next_port.to_string());
        tracing::info!(service = %service_type, old_port, new_port = next_port, "upgrade: updated {} env var", port_env);
    }

    write_progress(
        &conn,
        &upgrade_key,
        "complete",
        &service_type,
        old_port,
        serde_json::json!({"new_port": next_port}),
        Some(&new_instance_key),
    )
    .await;
    clear_progress(&conn, &upgrade_key, Some(&new_instance_key)).await;
}

/// Resolve the instance a port-key (`{ip}:{port}`) refers to.
///
/// The Valkey registry stores instances in per-type hashes keyed `{ip}:{port}`
/// without the service type in the field (captain DESIGNS §3): during a
/// botched window SEVERAL services can hold rows for the same port, so a
/// bare key is ambiguous. A unique match resolves; zero matches are a
/// NotFound error; multiple services (or multiple pids of one service)
/// on the same key are an Ambiguous error listing the conflicting rows
/// - the operator must clean up before the action can target anything.
enum KeyResolution {
    /// Exactly one instance for the key.
    // Boxed: the instance record (~300 B of strings) dwarfs the message
    // variants; the enum is constructed per key resolution call.
    Unique(Box<store::ServiceInstance>),
    /// No instance for the key (message describes it).
    NotFound(String),
    /// Several instances share the key (message lists them).
    Ambiguous(String),
}

/// Resolve a key into one instance, or classify the ambiguity.
async fn resolve_instance(
    conn: &glide::GlideClient,
    key: &str,
) -> Result<KeyResolution, glide::GlideError> {
    let all = store::list_all(conn).await?;
    let matches: Vec<store::ServiceInstance> = all.into_iter().filter(|i| i.key == key).collect();
    match matches.len() {
        1 => Ok(KeyResolution::Unique(Box::new(
            matches.into_iter().next().unwrap(),
        ))),
        0 => Ok(KeyResolution::NotFound(format!(
            "instance not found: {key}"
        ))),
        _ => {
            let listing = matches
                .iter()
                .map(|i| format!("{} (pid {})", i.service_type, i.pid))
                .collect::<Vec<_>>()
                .join(", ");
            Ok(KeyResolution::Ambiguous(format!(
                "key {key} is ambiguous - {} registry rows share it; remove the stale rows first (services on this key: {listing})",
                matches.len()
            )))
        }
    }
}

/// List catalog.
pub async fn list_catalog(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    require_captain_policy(&state, &headers).await?;

    let catalog = state.live_catalog.read().unwrap();
    let entries: Vec<_> = catalog.values().cloned().collect();
    Ok(Json(entries))
}

/// `GET /v1/captain/alerts` - the crash-loop (give-up) alert list
/// (WARN-10): every service captain gave up on after MAX_RESTARTS and
/// has not yet recovered. Consumed by `captain services` (the
/// "manual intervention required" list printed after the instance
/// table) and by the RFW surfaces. The alert record is cleared
/// automatically when a (re)spawned instance reaches `Active` - this
/// endpoint always reflects the CURRENT give-up set, never history.
pub async fn list_alerts(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    require_captain_policy(&state, &headers).await?;

    let conn = state.conn.clone();
    let alerts = store::list_alerts(&conn).await.map_err(|e| {
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("valkey list-alerts: {e}"),
        )
    })?;
    let values: Vec<serde_json::Value> = alerts
        .into_iter()
        .map(|(svc, a)| {
            serde_json::json!({
                "service": svc,
                "restarts": a.restarts,
                "reason": a.reason,
                "log_path": a.log_path,
                "at": a.at,
            })
        })
        .collect();
    Ok(Json(values))
}

/// POST /v1/captain/add-catalog - hot-add an external service catalog.
///
/// POST /v1/captain/merge-catalog - merge catalog entries into the live catalog.
///
/// Takes catalog entries inline (no file). Used by `vertical enroll` when
/// captain is already running. Entries already have resolved binary_path.
///
/// Request body: `{ "entries": [ { service_type, binary, binary_path, ... }, ... ] }`
#[derive(Deserialize)]
/// Request body for mergecatalog.
pub struct MergeCatalogRequest {
    /// The entries - raw JSON so merge can distinguish "field absent"
    /// (keep the existing entry's value) from "field declared" (overwrite).
    /// A registry JSON that does not mention probe mode / ports must not
    /// flatten captain's per-service defaults (the proxy kill-loop incident:
    /// a bare `sentin8:proxy` registry entry reset the mgmt-port HTTP probe
    /// to the https://443 default via serde defaults, and captain SIGKILLed
    /// the healthy proxy every ~55s).
    pub entries: Vec<serde_json::Value>,
}

/// Handle merge catalog.
pub async fn merge_catalog(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<MergeCatalogRequest>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    // RCE boundary : entries carry a resolved `binary_path`
    // that a later `start-services` spawn will execute - this endpoint must
    // never be callable without passing the Shield `sentin8:captain:admin`
    // gate.
    require_captain_policy(&state, &headers).await?;

    let added: Vec<String> = {
        let mut catalog = state.live_catalog.write().unwrap();
        let mut added = Vec::new();
        for raw in req.entries {
            let service_type = raw
                .get("service_type")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if service_type.is_empty() {
                continue;
            }
            let declared = match serde_json::from_value::<ServiceCatalogEntry>(raw.clone()) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(service = %service_type, error = %e, "merge-catalog: bad entry - skipping");
                    continue;
                }
            };
            let new_entry = match catalog.get(&service_type) {
                // Existing entry (platform defaults or an earlier merge): only the
                // fields the incoming JSON EXPLICITLY declares overwrite it - absent
                // fields keep the current values (serde defaults never flatten).
                Some(existing) => {
                    let mut merged = existing.clone();
                    if let Some(obj) = raw.as_object() {
                        // String fields.
                        for (key, target) in [
                            ("binary", &mut merged.binary),
                            ("binary_path", &mut merged.binary_path),
                        ] {
                            if let Some(v) = obj.get(key) {
                                match serde_json::from_value::<String>(v.clone()) {
                                    Ok(parsed) => *target = parsed,
                                    Err(e) => tracing::warn!(
                                        service = %service_type, field = key, error = %e,
                                        "merge-catalog: bad field value - keeping existing"
                                    ),
                                }
                            }
                        }
                        // u16 fields.
                        for (key, target) in [
                            ("fixed_port", &mut merged.fixed_port),
                            ("health_port", &mut merged.health_port),
                        ] {
                            if let Some(v) = obj.get(key).and_then(|v| v.as_u64()) {
                                if v <= u16::MAX as u64 {
                                    *target = v as u16;
                                }
                            }
                        }
                        // bool fields.
                        for (key, target) in [
                            ("use_http_health", &mut merged.use_http_health),
                            ("upgrade_stop_first", &mut merged.upgrade_stop_first),
                        ] {
                            if let Some(v) = obj.get(key).and_then(|v| v.as_bool()) {
                                *target = v;
                            }
                        }
                        if let Some(v) = obj.get("start_priority").and_then(|v| v.as_i64()) {
                            merged.start_priority = v as i16;
                        }
                        if let Some(v) = obj.get("extra_env").and_then(|v| v.as_object()) {
                            for (k, val) in v {
                                if let Some(s) = val.as_str() {
                                    merged.extra_env.insert(k.clone(), s.to_string());
                                }
                            }
                        }
                        if let Some(v) = obj.get("database_env_vars").and_then(|v| v.as_array()) {
                            merged.database_env_vars = v
                                .iter()
                                .filter_map(|x| x.as_str().map(String::from))
                                .collect();
                        }
                    }
                    merged
                }
                None => {
                    added.push(service_type.clone());
                    declared
                }
            };
            catalog.insert(service_type, new_entry);
        }
        added
    };

    tracing::info!(services = added.len(), "merge-catalog: merged entries");

    Ok(Json(serde_json::json!({
        "merged_services": added,
    })))
}

/// POST /v1/captain/start-services - start specific services by type name.
///
/// Takes a list of service types. Finds them in the live catalog, spawns
/// any that aren't already running.
///
/// Request body: `{ "service_types": ["bank8-ledger", "bank8-payments", ...] }`
#[derive(Deserialize)]
/// Request body for startservices.
pub struct StartServicesRequest {
    /// The service types.
    pub service_types: Vec<String>,
}

/// Spawn ONE service type that has no instance yet (captain DESIGN §5.10.1;
/// shared by the operator start-services API and the CAPT-ALERT-2
/// last-resort respawner): placement gate → port pick → spawn → register →
/// publish. Returns the new port, or a human-readable skip reason.
///
/// RCE boundary - callers already gate execution: the API site behind
/// Shield `sentin8:captain:admin`; the respawner is captain-internal.
pub(crate) async fn spawn_one_service(
    conn: &glide::GlideClient,
    local_ip: &str,
    port_range: (u16, u16),
    service_type: &str,
    entry: &ServiceCatalogEntry,
) -> Result<u16, String> {
    // Placement gate (FLEET-1, DESIGN §11.3): every spawn site consults the
    // same seam - a refusal is a structured reject with the reason.
    let all = store::list_all(conn)
        .await
        .map_err(|e| format!("valkey list-all: {e}"))?
        .into_iter()
        .filter(|i| i.status != "Stopped" && i.status != "Killed")
        .map(|i| crate::placement::ObservedInstance {
            ip: i.local_ip,
            service_type: i.service_type,
        })
        .collect::<Vec<_>>();
    let (local_obs, fleet_obs): (
        Vec<crate::placement::ObservedInstance>,
        Vec<crate::placement::ObservedInstance>,
    ) = all
        .iter()
        .cloned()
        .partition::<Vec<_>, _>(|i| i.ip == local_ip);
    if let Err(refusal) =
        crate::placement::placement_admits(entry, local_ip, &local_obs, &fleet_obs)
    {
        let message = format!(
            "placement gate refused service '{}': {} ({})",
            service_type,
            refusal.reason(),
            refusal.as_str()
        );
        tracing::warn!(
            service = service_type,
            placement = %entry.placement,
            reason = refusal.as_str(),
            "spawn: placement gate refused"
        );
        return Err(message);
    }

    let port = if entry.fixed_port > 0 {
        entry.fixed_port
    } else {
        let instances = store::list_for_ip(conn, local_ip)
            .await
            .map_err(|e| format!("valkey list-for-ip: {e}"))?;
        let used: std::collections::HashSet<u16> = instances.iter().map(|i| i.local_port).collect();
        let mut p = port_range.0;
        // RESPAWNPORT-1: the registry's used-set alone is not enough -
        // a live listener outside the registry (a boot-loop orphan, a
        // fixed-port service the rows were deleted from) still holds the
        // port. The boot-spawn path checks `is_port_in_use`; this path
        // must too, or every last-resort respawn lands on the same
        // occupied port and bind-fails forever.
        while used.contains(&p) || crate::server::is_port_in_use(p) {
            p = match p.checked_add(1) {
                Some(pp) if pp <= port_range.1 => pp,
                _ => return Err("port range exhausted".to_string()),
            };
        }
        p
    };

    let mut cmd = entry.spawn_command(port);
    let child = cmd
        .spawn()
        .map_err(|e| format!("spawn {service_type}: {e}"))?;
    let pid = child.id().ok_or_else(|| "no pid".to_string())?;
    crate::supervisor::register_child(pid, child);

    let inst = store::ServiceInstance {
        key: store::ServiceInstance::make_key(service_type, local_ip, port),
        service_type: service_type.to_string(),
        local_ip: local_ip.to_string(),
        local_port: port,
        pid,
        status: "Starting".to_string(),
        start_priority: entry.start_priority,
        cpu_avg_1m: 0.0,
        memory_avg_1m: 0.0,
        rss_mb_avg_1m: 0.0,
        latency_avg_1m_ms: 0.0,
        last_health_check: None,
        started_at: Some(chrono::Utc::now().timestamp()),
        version: String::new(),
        build_hash: String::new(),
        restarts: 0,
        errors: 0,
        warnings: 0,
        api_calls: 0,
    };
    store::upsert_instance(conn, &inst)
        .await
        .map_err(|e| format!("valkey upsert: {e}"))?;

    let _: () = glide::cmd("PUBLISH")
        .arg("captain:changed")
        .arg("")
        .query_async(conn)
        .await
        .unwrap_or(());

    tracing::info!(service = service_type, port, pid, "spawn: spawned");
    Ok(port)
}

/// Handle start services.
pub async fn start_services(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<StartServicesRequest>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    // RCE boundary : resolves service types through the live
    // catalog and executes their `binary_path` as captain children with the
    // full inherited environment - always behind the Shield
    // `sentin8:captain:admin` gate.
    require_captain_policy(&state, &headers).await?;

    // Find which services are not yet running.
    let conn = state.conn.clone();
    let existing = store::list_for_ip(&conn, &state.config.local_ip)
        .await
        .unwrap_or_default();
    let existing_types: std::collections::HashSet<String> =
        existing.iter().map(|i| i.service_type.clone()).collect();

    let port_range = state.config.port_range;
    let mut started: Vec<String> = Vec::new();

    // The API surfaces distinguish three caller-visible outcomes, mapped
    // onto the shared seam's single `Result<u16, String>`:
    //   placement refusal  → 409 (structured, the operator sees WHY);
    //   spawn/upsert error → 500 with the reason;
    //   skip conditions    → skipped silently in the response summary.
    for service_type in &req.service_types {
        if existing_types.contains(service_type) {
            continue; // already running
        }
        let entry = {
            let catalog = state.live_catalog.read().unwrap();
            match catalog.get(service_type) {
                Some(e) => e.clone(),
                None => {
                    tracing::warn!(
                        service = service_type,
                        "start-services: not in catalog - skipping"
                    );
                    continue;
                }
            }
        };
        let conn_spawn = state.conn.clone();
        match spawn_one_service(
            &conn_spawn,
            &state.config.local_ip,
            port_range,
            service_type,
            &entry,
        )
        .await
        {
            Ok(port) => {
                started.push(service_type.clone());
                tracing::info!(service = service_type, %port, "start-services: spawned");
            }
            Err(reason) if reason.starts_with("placement gate refused") => {
                return Err((axum::http::StatusCode::CONFLICT, reason));
            }
            Err(reason) => {
                return Err((axum::http::StatusCode::INTERNAL_SERVER_ERROR, reason));
            }
        }
    }

    Ok(Json(serde_json::json!({
        "started_services": started,
    })))
}

/// `POST /v1/captain/instances` - the remote-spawn endpoint (FLEET-4,
/// DESIGN §11.4).
///
/// This is the SAME spawn path as `/v1/captain/start-services` (the target
/// resolves everything from its OWN catalog + operator env - the body
/// carries service types only, no machine-controlled parameters cross the
/// wire), behind a DIFFERENT authorization gate: the M2M `captain-remote`
/// workload's granular `sentin8:captain:instances:write` scope, or the
/// operator's `sentin8:captain:admin` for hand placement via the CLI.
///
/// Placement gates apply identically - a leader calling this on machine
/// Y for a service pinned elsewhere gets the same structured 409 as a
/// local operator would.
#[derive(Deserialize)]
/// Request body for remote instances.
pub struct RemoteInstancesRequest {
    /// The service types to spawn on THIS machine (the target resolves
    /// binary/ports/env from its own catalog - the wire carries no more
    /// than the types).
    pub service_types: Vec<String>,
}

/// Handle remote instances (the remote-spawn entry point).
pub async fn remote_instances(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<RemoteInstancesRequest>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    require_instances_write(&state, &headers).await?;
    // Reuse the full start-services body (placement gate + catalog
    // resolution + port allocation + registry upsert). The gate difference
    // is the ONLY difference between the surfaces.
    let resp = start_services(
        State(state),
        headers,
        Json(StartServicesRequest {
            service_types: req.service_types,
        }),
    )
    .await?;
    Ok(resp)
}
/// Usage:
/// curl http://localhost:3099/v1/captain/readiness
/// # or in scripts: until curl -sf.../readiness; do sleep 2; done
/// Handle readiness.
pub async fn readiness(
    State(state): State<AppState>,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    let conn = state.conn.clone();
    let instances = store::list_all(&conn)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Group Active instances by service_type.
    use std::collections::HashMap;
    let active_counts: HashMap<String, usize> = instances
        .iter()
        .filter(|i| i.status == "Active")
        .fold(HashMap::new(), |mut acc, i| {
            *acc.entry(i.service_type.clone()).or_insert(0) += 1;
            acc
        });

    // Check each catalog entry: does it have >= min_instances Active?
    let mut pending: Vec<serde_json::Value> = Vec::new();
    let catalog = state.live_catalog.read().unwrap();
    let total = catalog.len();
    for entry in catalog.values() {
        let active = *active_counts.get(&entry.service_type).unwrap_or(&0);
        if active < crate::catalog::MIN_INSTANCES as usize {
            let status = instances
                .iter()
                .find(|i| i.service_type == entry.service_type)
                .map(|i| i.status.as_str())
                .unwrap_or("missing");
            pending.push(serde_json::json!({
                "service": entry.service_type,
                "active": active,
                "required": crate::catalog::MIN_INSTANCES,
                "status": status,
            }));
        }
    }

    let ready = pending.is_empty();
    let body = serde_json::json!({
        "ready": ready,
        "ready_count": total - pending.len(),
        "total": total,
        "pending": pending,
    });

    if ready {
        Ok((axum::http::StatusCode::OK, Json(body)))
    } else {
        Ok((axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(body)))
    }
}

/// GET /v1/captain/autoscaler - cluster-autoscaler role status.
///
/// Surfaces the profile, backend, fleet size, and the elected leader IP so
/// operators can see the horizontal-scaling state without SSHing to machines.
/// Handle autoscaler status.
pub async fn autoscaler_status(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Result<impl IntoResponse, (axum::http::StatusCode, String)> {
    require_captain_policy(&state, &headers).await?;

    let conn = state.conn.clone();
    let machines = crate::provision::list_machines(&conn)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let fleet = crate::provision::count_fleet_machines(&conn)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let leader: Option<String> = glide::cmd("GET")
        .arg(crate::provision::AUTOSCALER_LOCK_KEY)
        .query_async(&conn)
        .await
        .unwrap_or(None);
    let last_provision: Option<String> = glide::cmd("GET")
        .arg(crate::provision::LAST_PROVISION_KEY)
        .query_async(&conn)
        .await
        .unwrap_or(None);
    let pending = crate::provision::list_pending(&conn)
        .await
        .unwrap_or_default();

    let config = &state.config;
    let body = serde_json::json!({
           "profile": config.provision_profile.as_str(),
           "backend": config.provision_backend,
           "max_machines": config.max_machines,
           "min_machines": config.min_machines,
           "provision_window_s": config.provision_window_s,
           "provision_cooldown_s": config.provision_cooldown_s,
           "provision_idle_window_s": config.provision_idle_window_s,
           "fleet_machines": fleet,
           "leader": leader.clone().unwrap_or_default(),
           "is_leader": leader.as_deref() == Some(std::process::id().to_string().as_str()),
           "last_provision_ts": last_provision.and_then(|s| s.parse::<i64>().ok()),
    // Pending requests awaiting operator approval (manual profile).
           "pending": pending.iter().map(|p| serde_json::json!({
               "kind": p.kind,
               "ip": p.ip,
               "busy_service": p.busy_service,
               "requested_at": p.requested_at,
           })).collect::<Vec<_>>(),
           "machines": machines.iter().map(|m| serde_json::json!({
               "ip": m.ip,
               "cpu_pct": m.cpu_pct,
               "mem_pct": m.mem_pct,
               "used_mb": m.used_mb,
               "ts": m.ts,
               "saturated": m.saturated,
               "saturated_service": m.saturated_service,
           })).collect::<Vec<_>>(),
       });
    Ok(Json(body))
}

/// POST /v1/captain/autoscaler/approve - operator decision on a pending
/// manual-profile request.
///
/// Body: `{"kind": "provision"|"deprovision", "ip": "10.x.x.x", "decision": "approve"|"reject"}`
/// `approve` executes the request through the configured backend (OpenTofu
/// or noop); `reject` discards it.
#[derive(Debug, Deserialize)]
/// Request body for autoscalerapprove.
pub struct AutoscalerApproveRequest {
    /// The request kind: `provision` or `deprovision`.
    pub kind: String, // "provision" | "deprovision"
    /// The machine address the request refers to.
    pub ip: String,
    /// The decision: `approve` or `reject`.
    pub decision: String, // "approve" | "reject"
}

/// Handle autoscaler approve.
pub async fn autoscaler_approve(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(req): Json<AutoscalerApproveRequest>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    require_captain_policy(&state, &headers).await?;
    if !matches!(req.decision.as_str(), "approve" | "reject") {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "decision must be \"approve\" or \"reject\"".into(),
        ));
    }
    if !matches!(req.kind.as_str(), "provision" | "deprovision") {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "kind must be \"provision\" or \"deprovision\"".into(),
        ));
    }
    let conn = state.conn.clone();
    let result = crate::provision::approve(&conn, &state.config, &req.kind, &req.ip, &req.decision)
        .await
        .map_err(|e| (axum::http::StatusCode::CONFLICT, e.to_string()))?;
    Ok(Json(result))
}

extern "C" {
    fn kill(pid: u32, sig: i32) -> i32;
}
unsafe fn kill_signal(pid: u32, sig: i32) -> i32 {
    kill(pid, sig)
}

#[cfg(test)]
mod readiness_tests {
    //! READYSCOPE-1: startup-stream accounting rides the boot scope.

    use super::*;

    fn instance(service_type: &str, port: u16, status: &str) -> store::ServiceInstance {
        store::ServiceInstance {
            key: store::ServiceInstance::make_key(service_type, "127.0.0.1", port),
            service_type: service_type.to_string(),
            local_ip: "127.0.0.1".to_string(),
            local_port: port,
            pid: 1,
            start_priority: 0,
            cpu_avg_1m: 0.0,
            memory_avg_1m: 0.0,
            rss_mb_avg_1m: 0.0,
            latency_avg_1m_ms: 0.0,
            last_health_check: None,
            started_at: None,
            version: String::new(),
            build_hash: String::new(),
            errors: 0,
            warnings: 0,
            api_calls: 0,
            restarts: 0,
            status: status.to_string(),
        }
    }

    fn catalog_entry(service_type: &str) -> ServiceCatalogEntry {
        ServiceCatalogEntry {
            service_type: service_type.to_string(),
            binary: "bin".into(),
            binary_path: String::new(),
            start_priority: 0,
            fixed_port: 0,
            health_port: 0,
            use_http_health: false,
            upgrade_stop_first: false,
            extra_env: Default::default(),
            database_env_vars: Vec::new(),
            web_root: String::new(),
            placement: String::new(),
            singleton: false,
        }
    }

    fn mk_catalog(types: &[&str]) -> HashMap<String, ServiceCatalogEntry> {
        types.iter().map(|t| (t.to_string(), catalog_entry(t))).collect()
    }

    #[test]
    fn scoped_accounting_counts_only_allowed_types() {
        let cat = mk_catalog(&["sentin8:auth", "sentin8:bff", "bank8:ledger"]);
        let allow: std::collections::HashSet<String> =
            ["sentin8:auth".to_string(), "sentin8:bff".to_string()].into();
        let set = readiness_accounting_types(Some(&allow), &cat);
        assert_eq!(set.len(), 2, "bank8:ledger must NOT be accounted");
        assert!(set.contains(&"sentin8:auth".to_string()));
        assert!(set.contains(&"sentin8:bff".to_string()));
    }

    #[test]
    fn unscoped_accounting_is_the_full_union() {
        let cat = mk_catalog(&["sentin8:auth", "bank8:ledger"]);
        let set = readiness_accounting_types(None, &cat);
        assert_eq!(set.len(), 2, "unscoped boot accounts the whole union");
    }

    #[test]
    fn scoped_totals_exclude_never_spawned_verticals() {
        // 19 scoped types: 18 Active + 1 crash-looped → 18/19, ONE pending.
        let cat = mk_catalog(&["sentin8:sign", "bank8:ledger", "sentin8:auth"]);
        let allow: std::collections::HashSet<String> = ["sentin8:sign".to_string(), "sentin8:auth".to_string()].into();
        let set = readiness_accounting_types(Some(&allow), &cat);
        let active: HashMap<String, usize> = [("sentin8:auth".to_string(), 1usize)].into();
        let instances = vec![instance("sentin8:auth", 8003, "Active")];
        let (ready, pending) = readiness_accounting(&set, &active, &instances);
        assert_eq!((ready, set.len()), (1, 2));
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0]["service"], "sentin8:sign");
        assert_eq!(pending[0]["status"], "missing");
    }

    #[test]
    fn all_scoped_active_is_ready() {
        let cat = mk_catalog(&["sentin8:auth", "sentin8:bff"]);
        let allow: std::collections::HashSet<String> =
            ["sentin8:auth".to_string(), "sentin8:bff".to_string()].into();
        let set = readiness_accounting_types(Some(&allow), &cat);
        let active: HashMap<String, usize> = [
            ("sentin8:auth".to_string(), 1usize),
            ("sentin8:bff".to_string(), 1usize),
        ]
        .into();
        let instances = vec![
            instance("sentin8:auth", 8003, "Active"),
            instance("sentin8:bff", 8018, "Active"),
        ];
        let (ready, pending) = readiness_accounting(&set, &active, &instances);
        assert_eq!((ready, set.len()), (2, 2));
        assert!(pending.is_empty(), "scoped boot completes ready");
    }
}
