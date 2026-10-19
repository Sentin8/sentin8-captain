// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Captain Admin UI handlers - RFW definitions for the Dash.
//!
//! Served from `GET /v1/admin/ui/{page}` (page definitions), `GET
//! /v1/admin/{resource}` (data rows), and `POST /v1/admin/...` (row actions),
//! rendered by Sentin8:Dash at runtime (RFW - the dash has zero compile-time
//! knowledge of these pages). The autoscaler overview page surfaces the
//! machine auto-provisioning state and the manual-profile
//! pending-approval queue with inline approve/reject row actions.
//!
//! Route shape for row actions: the dash renderer substitutes ONLY `{id}`
//! from the row's `id` field - the pending-request
//! rows therefore carry a colon-joined `id` = `{kind}:{ip}` so both the
//! kind and the target IP ride in one path segment.
//!
//! Authorization mirrors the management API: the same Shield step-5 gate
//! (`sentin8:captain:admin`) protects every page, data, and action endpoint
//! ( - the RCE surface argument applies to the approve action too).

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::widget::{
    ButtonType, RemoteWidget, TextAlign, WidgetButton, WidgetCard, WidgetDataTable,
    WidgetDataTableColumn, WidgetText, WidgetTextType,
};
use sentin8::rfw::{page::AdminPage, AdminUiResponse};

use crate::handlers::AppState;
use crate::provision;

/// `GET /v1/admin/ui/{page}` - returns the RFW page definition as JSON.
///
/// Pages:
/// - `overview` - autoscaler state cards (profile, backend, fleet,
///   leader) + the pending-approval table (manual profile)
/// - `machines` - per-machine host CPU/mem + saturation flags
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    // Step 5 - Shield decides. Same gate as every other
    // management endpoint - the RFW surface exposes the same approve action
    // the HTTP API does, so it must not be weaker.
    crate::handlers::require_captain_policy(&state, &headers).await?;
    crate::handlers::require_captain_policy(&state, &headers).await?;
    let config = &state.config;
    let def = match page.as_str() {
        "overview" => AdminPage::new("Machine Autoscaler")
            .widget(card(
                "Profile",
                &format!(
                    "{} - {}",
                    config.provision_profile.as_str(),
                    profile_description(config.provision_profile),
                ),
            ))
            .widget(card(
                "Backend",
                &backend_description(&config.provision_backend),
            ))
            .widget(card(
                "Fleet",
                &format!(
                    "Max {max} machine(s), min {min}. Cooldown {cooldown}s, saturation window {window}s, idle window {idle}s.",
                    max = config.max_machines,
                    min = config.min_machines,
                    cooldown = config.provision_cooldown_s,
                    window = config.provision_window_s,
                    idle = config.provision_idle_window_s,
                ),
            ))
            .widget(card("Election", &leader_description(&state).await))
            .widget(table_with_actions(
                vec![
                    col("id", "Kind / Trigger IP"),
                    col("busy_service", "Busy service"),
                    col("requested_at", "Requested"),
                ],
                "/autoscaler-pending",
                vec![
                    row_action_post("Approve", "autoscaler-approve"),
                    row_action_post("Reject", "autoscaler-reject"),
                ],
            ))
            .build(),
        "machines" => AdminPage::new("Fleet Machines")
            .widget(table_with_actions(
                vec![
                    col("ip", "Machine"),
                    col("cpu_pct", "Host CPU %"),
                    col("mem_pct", "Host Mem %"),
                    col("used_mb", "Used MB"),
                    col("saturated", "Saturated"),
                    col("saturated_service", "Busy service"),
                ],
                "/autoscaler-machines",
                vec![],
            ))
            .build(),
        _ => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ));
        }
    };
    Ok(Json(AdminUiResponse::page(def)))
}

/// `GET /v1/admin/{resource}` - data rows for the admin UI tables.
///
/// Resources:
/// - `autoscaler-pending` - pending provision/deprovision requests
/// - `autoscaler-machines` - per-machine host samples + saturation
/// - `autoscaler-status` - one-row summary (profile/backend/fleet/leader)
pub async fn get_admin_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(resource): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    crate::handlers::require_captain_policy(&state, &headers).await?;
    let conn = state.conn.clone();
    let config = &state.config;
    let rows: Vec<serde_json::Value> = match resource.as_str() {
        "autoscaler-pending" => {
            let pending = provision::list_pending(&conn).await.unwrap_or_default();
            pending
                .iter()
                .map(|p| {
                    // The row id carries BOTH decision dimensions - the
                    // renderer substitutes only `{id}` , so
                    // the row-action endpoints split it back apart.
                    serde_json::json!({
                        "id": format!("{}:{}", p.kind, p.ip),
                        "kind": p.kind,
                        "ip": p.ip,
                        "busy_service": p.busy_service,
                        "requested_at": p.requested_at,
                    })
                })
                .collect()
        }
        "autoscaler-machines" => {
            let machines = provision::list_machines(&conn).await.unwrap_or_default();
            machines
                .iter()
                .map(|m| {
                    serde_json::json!({
                        "id": m.ip,
                        "ip": m.ip,
                        "cpu_pct": m.cpu_pct,
                        "mem_pct": m.mem_pct,
                        "used_mb": m.used_mb,
                        "saturated": if m.saturated { "YES" } else { "no" },
                        "saturated_service": m.saturated_service,
                    })
                })
                .collect()
        }
        "autoscaler-status" => {
            let leader: Option<String> = glide::cmd("GET")
                .arg(provision::AUTOSCALER_LOCK_KEY)
                .query_async(&conn)
                .await
                .unwrap_or(None);
            let fleet = provision::count_fleet_machines(&conn).await.unwrap_or(0);
            vec![serde_json::json!({
                "id": "autoscaler",
                "profile": config.provision_profile.as_str(),
                "backend": config.provision_backend,
                "fleet_machines": fleet,
                "max_machines": config.max_machines,
                "min_machines": config.min_machines,
                "leader": leader.unwrap_or_default(),
            })]
        }
        _ => vec![],
    };
    Ok(Json(serde_json::Value::Array(rows)))
}

/// `POST /v1/admin/autoscaler-approve` - row action: approve a pending
/// request. The row id is `{kind}:{ip}` (colon-joined - the renderer
/// substitutes only `{id}`).
pub async fn approve_row(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let (kind, ip) = split_pending_id(&id)?;
    execute_decision(&state, &headers, &kind, &ip, "approve").await
}

/// `POST /v1/admin/autoscaler-reject` - row action: reject (discard) a
/// pending request. Same `{kind}:{ip}` row-id shape as approve.
pub async fn reject_row(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let (kind, ip) = split_pending_id(&id)?;
    execute_decision(&state, &headers, &kind, &ip, "reject").await
}

fn split_pending_id(id: &str) -> Result<(String, String), (axum::http::StatusCode, String)> {
    // Split back-to-front: the IP is everything before the FIRST colon
    // pair boundary - ids are `{kind}:{ip}` and ip itself contains
    // colons only in IPv6 (not supported by the registry model).
    match id.split_once(':') {
        Some((kind, ip)) if kind == "provision" || kind == "deprovision" => {
            Ok((kind.to_string(), ip.to_string()))
        }
        _ => Err((
            axum::http::StatusCode::BAD_REQUEST,
            format!("malformed pending-request id `{id}` - expected `{{kind}}:{{ip}}`"),
        )),
    }
}

async fn execute_decision(
    state: &AppState,
    headers: &HeaderMap,
    kind: &str,
    ip: &str,
    decision: &str,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    crate::handlers::require_captain_policy(state, headers).await?;
    let conn = state.conn.clone();
    provision::approve(&conn, &state.config, kind, ip, decision)
        .await
        .map_err(|e| (axum::http::StatusCode::CONFLICT, e.to_string()))?;
    // The renderer navigates ONLY on a redirect response - return to the
    // overview page so the pending table refreshes with the decision
    // applied. (The JSON body of a POST is otherwise ignored by the
    // renderer - the redirect route IS the success path.)
    Ok(Json(
        serde_json::to_value(AdminUiResponse::redirect("overview")).unwrap(),
    ))
}

// ── Helpers (same pattern as acme/db admin_ui.rs) ─────────────────────

fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}

fn col(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: false,
        width: None,
        format: None,
    }
}

fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("Nothing pending.".into()),
        row_link: None,
        row_actions,
    })
}

fn row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: if label == "Reject" {
            ButtonType::Danger
        } else {
            ButtonType::Primary
        },
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}

/// Human description of the profile for the overview card.
fn profile_description(p: provision::ProvisionProfile) -> &'static str {
    match p {
        provision::ProvisionProfile::Auto => {
            "auto - provisions up to MAX_MACHINES when a machine saturates (dry-run with the noop backend)"
        }
        provision::ProvisionProfile::Manual => {
            "manual - saturation records a pending request; an operator approves below"
        }
        provision::ProvisionProfile::Never => {
            "never - the autoscaler role is inert; saturation stays a log line"
        }
    }
}

/// Backend description for the overview card.
fn backend_description(backend: &str) -> String {
    match backend {
        "noop" => "noop (dry-run) - decisions are recorded and alerted, nothing is created".into(),
        b @ ("cloud" | "hypervisor" | "bare-metal" | "docker") => {
            format!("{b} - OpenTofu module in SENTIN8_CAPTAIN_TOFU_DIR")
        }
        other => format!("{other} (unknown - falls back to noop)"),
    }
}

/// Election description for the overview card (reads the leader lock).
async fn leader_description(state: &AppState) -> String {
    let conn = state.conn.clone();
    let leader: Option<String> = glide::cmd("GET")
        .arg(provision::AUTOSCALER_LOCK_KEY)
        .query_async(&conn)
        .await
        .unwrap_or(None);
    let fleet = provision::count_fleet_machines(&conn).await.unwrap_or(0);
    let is_me = leader.as_deref() == Some(std::process::id().to_string().as_str());
    match leader {
        Some(l) if is_me => {
            format!("This captain holds the autoscaler role ({l}). Fleet: {fleet} machine(s).")
        }
        Some(l) => format!("Captain at {l} holds the autoscaler role. Fleet: {fleet} machine(s)."),
        None => format!("No leader elected. Fleet: {fleet} machine(s)."),
    }
}
