// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Captain configuration loaded from environment variables.

use std::collections::HashMap;
use std::env;

use crate::catalog::ServiceCatalogEntry;

/// Captain configuration: runtime parameters + the static service catalog.
///
/// All `SENTIN8_CAPTAIN_*` env vars override the defaults. The catalog is
/// seeded with the standard Sentin8 service set (see `default_catalog`) and
/// extended by every external `SENTIN8_CAPTAIN_CATALOG_PATHS` entry — the
/// catalog is ALWAYS the full union. `SENTIN8_SERVICES` (comma-separated
/// colon identities) is the **boot-spawn allow-list** (`boot_allow`): it
/// filters which tiers the boot spawn starts, never the catalog contents
/// (see DESIGN §3 "Catalog and the boot-spawn filter"). When unset, boot
/// spawns the whole catalog.
#[derive(Debug, Clone)]
/// Configuration for captain.
pub struct CaptainConfig {
    /// Inbound HTTP port for the Captain management API (default 3099).
    /// The port.
    pub port: u16,
    /// Valkey URL for the orch_services registry (no PostgreSQL needed).
    /// The valkey URL.
    pub valkey_url: String,
    /// The routable IP of *this* machine on the network. Captain owns only
    /// `orch_services` rows where `local_ip = SENTIN8_CAPTAIN_LOCAL_IP`. Required
    /// passed via `--local-ip` to `sentin8 captain start`.
    /// The local ip.
    pub local_ip: String,
    /// Static service catalog: `service_type -> ServiceCatalogEntry`.
    /// Always the FULL union (built-in + external) — never pruned by
    /// SENTIN8_SERVICES (a boot-spawn filter, not a catalog prune — §3).
    /// The catalog.
    pub catalog: HashMap<String, ServiceCatalogEntry>,
    /// Boot-spawn allow-list from `SENTIN8_SERVICES` (colon-canonical).
    /// `None` = boot spawns the whole catalog. Consulted ONLY by the boot
    /// spawn loop — never by the API handlers (they resolve the live
    /// catalog).
    /// The boot spawn allow-list.
    pub boot_allow: Option<std::collections::HashSet<String>>,
    /// Max concurrent spawns within a priority tier (default 8).
    /// The start concurrency.
    pub start_concurrency: usize,
    /// Monitor loop tick interval (default 3s).
    /// The monitor tick s.
    pub monitor_tick_s: u64,
    /// Health probe failure threshold before a live process is killed
    /// and restarted (default 3 ticks).
    /// The health probe failures.
    pub health_probe_failures: u32,
    /// Cooldown after which `restarts` resets to 0 once `Active` (default 300s).
    /// The cooldown reset s.
    pub cooldown_reset_s: i64,
    /// TLS-cert warm-up grace: a LIVE process whose probes fail with a
    /// TLS warm-up signature — its on-demand server cert has not landed
    /// from acme yet (alert `AccessDenied`, certificate/handshake error
    /// text, or a connect-level failure while the resolver waits for the
    /// first cert) — is not killed for `cert_grace_s` seconds since
    /// start (default 120s). Fresh installs during fleet-wide cold
    /// starts / retry storms previously got mass-killed after 3 failed
    /// probes while their cert fetch was still queued behind the storm
    /// (CAPT-PROBE-3, captain DESIGN §5.10.2). Failures persisting PAST the
    /// window count again toward the normal kill path. 0 disables.
    pub cert_grace_s: i64,
    /// After MAX_RESTARTS give-up, captain keeps ONE slow last-resort
    /// respawn attempt per interval (default 300s) for every alerted
    /// service — an operator-away failure self-recovers instead of
    /// staying parked until manual intervention (the alert stays raised
    /// until the service reaches Active, which clears it). 0 disables
    /// (the manual-intervention-parked give-up semantics)
    /// (CAPT-ALERT-2, captain DESIGN §5.10.1).
    pub last_resort_respawn_s: i64,
    /// Drain window (seconds) between marking an instance `Inactive` and
    /// sending SIGTERM during a stop / upgrade (default 10s).
    /// The upgrade drain s.
    pub upgrade_drain_s: u64,
    /// Post inbox alert operator user id (system scope: sys org / ops env).
    #[allow(dead_code)]
    /// on call operator identifier.
    pub on_call_operator_id: Option<uuid::Uuid>,
    /// Global port range for auto-assigning instance ports. Captain assigns
    /// ports sequentially starting from `port_range.0`
    /// (`sentin8::config::port_pool_low` = base+2). The first service
    /// instance gets base+2, the next base+3, etc. When scaling up a
    /// service to a second instance, Captain picks the next free port in
    /// this range — NOT a per-service range — so the global port space is
    /// shared across all services on this machine.
    pub port_range: (u16, u16),
    /// Machine auto-provisioning profile. `Auto` (default)
    /// enables the cluster-autoscaler role up to `MAX_MACHINES` with cooldown
    /// + scale-in — with the default `noop` backend that is a dry-run.
    /// `Manual` requires operator approval; `Never` disables the role.
    /// The provision profile.
    pub provision_profile: crate::provision::ProvisionProfile,
    /// Provisioner backend selector. `noop` (default) is
    /// dry-run; `cloud`/`hypervisor`/`bare-metal` all execute OpenTofu
    /// (`tofu apply`) against the module dir `SENTIN8_CAPTAIN_TOFU_DIR`.
    /// The provision backend.
    pub provision_backend: String,
    /// Fleet-wide machine cap — the autoscaler never provisions beyond this.
    /// Maximum machines.
    pub max_machines: u32,
    /// Fleet-wide machine floor — scale-in never deprovisions below this.
    /// Minimum machines.
    pub min_machines: u32,
    /// Sustained-saturation window (seconds) before provisioning a machine.
    /// The provision window s.
    pub provision_window_s: u64,
    /// Cooldown (seconds) between machine provisions.
    /// The provision cooldown s.
    pub provision_cooldown_s: u64,
    /// Idle window (seconds) before a scale-in candidate is deprovisioned.
    /// The provision idle window s.
    pub provision_idle_window_s: u64,
}

impl CaptainConfig {
    /// Handle from env.
    pub fn from_env() -> Self {
        let valkey_url = env::var("SENTIN8_CAPTAIN_VALKEY_URL").unwrap_or_else(|_| {
            // VALKEYDERIVE-1: override chain → else the plane-derived URL.
            std::env::var("VALKEY_URL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| sentin8::config::service_valkey_url())
        });

        let mut catalog = default_catalog();
        // SENTIN8_SERVICES: comma-separated colon-identity allow-list — a
        // BOOT-SPAWN FILTER, not a catalog prune (DESIGN §3 "Catalog and
        // the boot-spawn filter"). When set, the boot spawn loop starts
        // ONLY those services (dev trimmed boots / fleet-subset machines);
        // the catalog itself stays the FULL union so /start-services,
        // per-instance actions, placement, and remote spawn can name any
        // registered type at any time. Accepts the canonical colon
        // identity (`sentin8:auth`), the worker alias
        // (`bank8:payments:w`), and legacy hyphen forms (`sentin8-auth`,
        // `bank8-payments-worker`) — all canonicalized to the colon form.
        // Example: SENTIN8_SERVICES=sentin8:auth,sentin8:bff,sentin8:bus
        // When unset, boot spawns everything (full fleet is the default).
        let boot_allow = env::var("SENTIN8_SERVICES").ok().map(|managed| {
            managed
                .split(',')
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(normalize_service_type)
                .collect::<std::collections::HashSet<String>>()
        });

        // Load external service catalogs. Captain's built-in catalog only
        // contains sentin8 platform services. External services (from bank8,
        // hotel8, etc.) are registered via catalog.json files, pointed to by
        // the SENTIN8_CAPTAIN_CATALOG_PATHS env var (comma-separated paths).
        //
        // This keeps sentin8 decoupled from verticals — captain doesn't know
        // or care what domains exist. It just reads JSON from given paths.
        if let Ok(paths) = env::var("SENTIN8_CAPTAIN_CATALOG_PATHS") {
            for path in paths.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                match std::fs::read_to_string(path) {
                    Ok(json) => {
                        match serde_json::from_str::<Vec<ServiceCatalogEntry>>(&json) {
                            Ok(entries) => {
                                for entry in entries {
                                    // FULL union — never filtered by
                                    // SENTIN8_SERVICES (boot-spawn filter
                                    // only — DESIGN §3).
                                    catalog.insert(entry.service_type.clone(), entry);
                                }
                                tracing::info!(
                                    path,
                                    count = catalog.len(),
                                    "loaded external service catalog"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(path, error = %e, "failed to parse catalog.json — skipping");
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(path, error = %e, "failed to read catalog.json — skipping");
                    }
                }
            }
        }

        // TLS-RLS-4 (design/sentin8-vertical-data-plane-contract.md §VDC.7):
        // derive the platform-plane hostname label map from the RUNTIME
        // CATALOG — registry-driven, zero hardcoded verticals. The
        // database-free TLS resolver in every spawned service maps
        // `{label}.ops.sys.{domain}` statically from this env var (its
        // core-platform leaf default covers only `sentin8:*` services;
        // vertical subdomains ride this map). Labels: platform services
        // use their leaf; catalog entries may override via `extra_env`
        // `sentin8_subdomain`.
        let labels: Vec<String> = catalog
            .values()
            .filter_map(|e| {
                let sub = e
                    .extra_env
                    .get("sentin8_subdomain")
                    .cloned()
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| sentin8::config::service_dash_form(&e.service_type));
                Some(format!("{sub}:{}", e.service_type))
            })
            .collect();
        if !labels.is_empty() {
            let joined = labels.join(",");
            // SAFETY: config-load path, single-threaded boot window.
            std::env::set_var("SENTIN8_TLS_PLATFORM_LABELS", joined);
            tracing::info!(
                count = labels.len(),
                "derived SENTIN8_TLS_PLATFORM_LABELS from the runtime catalog"
            );
        }

        Self {
            port: env::var("SENTIN8_CAPTAIN_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(sentin8::config::captain_port),
            valkey_url,
            local_ip: env::var("SENTIN8_CAPTAIN_LOCAL_IP")
                .expect("SENTIN8_CAPTAIN_LOCAL_IP must be set — pass --local-ip <IP> to 'sentin8 captain start'"),
            catalog,
            boot_allow,
            start_concurrency: env::var("SENTIN8_CAPTAIN_START_CONCURRENCY")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8),
            monitor_tick_s: env::var("SENTIN8_CAPTAIN_MONITOR_TICK_S")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3),
            health_probe_failures: env::var("SENTIN8_CAPTAIN_HEALTH_PROBE_FAILURES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(3),
            cooldown_reset_s: env::var("SENTIN8_CAPTAIN_COOLDOWN_RESET_S")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(300),
            cert_grace_s: env::var("SENTIN8_CAPTAIN_CERT_GRACE_S")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(120),
            last_resort_respawn_s: env::var("SENTIN8_CAPTAIN_LAST_RESORT_RESPAWN_S")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(300),
            upgrade_drain_s: env::var("SENTIN8_CAPTAIN_UPGRADE_DRAIN_S")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            on_call_operator_id: env::var("SENTIN8_CAPTAIN_ON_CALL_OPERATOR_ID")
                .ok()
                .and_then(|s| uuid::Uuid::parse_str(&s).ok()),
            port_range: {
                let low = env::var("SENTIN8_CAPTAIN_PORT_RANGE_LOW")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(sentin8::config::port_pool_low);
                let high = env::var("SENTIN8_CAPTAIN_PORT_RANGE_HIGH")
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or_else(sentin8::config::port_pool_high);
                (low, high)
            },
            provision_profile: env::var("SENTIN8_CAPTAIN_PROVISION_PROFILE")
                .ok()
                .as_deref()
                .map(|s| crate::provision::ProvisionProfile::parse(Some(s)))
                .unwrap_or(crate::provision::ProvisionProfile::Auto),
            provision_backend: env::var("SENTIN8_CAPTAIN_PROVISION_BACKEND")
                .unwrap_or_else(|_| "noop".to_string()),
            max_machines: env::var("SENTIN8_CAPTAIN_MAX_MACHINES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1),
            min_machines: env::var("SENTIN8_CAPTAIN_MIN_MACHINES")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1),
            provision_window_s: env::var("SENTIN8_CAPTAIN_PROVISION_WINDOW_S")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(crate::catalog::PROVISION_WINDOW_S),
            provision_cooldown_s: env::var("SENTIN8_CAPTAIN_PROVISION_COOLDOWN_S")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(crate::catalog::PROVISION_COOLDOWN_S),
            provision_idle_window_s: env::var("SENTIN8_CAPTAIN_PROVISION_IDLE_WINDOW_S")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(crate::catalog::PROVISION_IDLE_WINDOW_S),
        }
    }
}

/// Normalize a service type token from `SENTIN8_SERVICES` to the canonical
/// colon identity form (`{vertical}:{service}[:worker]` — see
/// `.md` ).
///
/// Accepts:
/// - Canonical: `sentin8:auth`, `bank8:ledger`, `bank8:payments:worker`
/// - Worker alias: `bank8:payments:w` → `:worker`
/// - Legacy hyphen: `sentin8-auth`, `bank8-payments-worker` (accepted for
/// operator muscle memory)
///
/// Canonicalization delegates to `sentin8::config::canonical_service_type`.
fn normalize_service_type(token: &str) -> String {
    sentin8::config::canonical_service_type(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_canonical() {
        assert_eq!(normalize_service_type("sentin8:auth"), "sentin8:auth");
        assert_eq!(normalize_service_type("sentin8:acme"), "sentin8:acme");
        assert_eq!(normalize_service_type("sentin8:proxy"), "sentin8:proxy");
        assert_eq!(normalize_service_type("sentin8:bus"), "sentin8:bus");
        assert_eq!(normalize_service_type("test:ledger"), "test:ledger");
        assert_eq!(normalize_service_type("test:payments"), "test:payments");
        assert_eq!(normalize_service_type("test:pms"), "test:pms");
    }

    #[test]
    fn normalize_worker_alias() {
        assert_eq!(
            normalize_service_type("bank8:payments:w"),
            "bank8:payments:worker"
        );
        assert_eq!(
            normalize_service_type("bank8:payments:worker"),
            "bank8:payments:worker"
        );
    }

    #[test]
    fn normalize_legacy_hyphen_forms() {
        assert_eq!(normalize_service_type("sentin8-auth"), "sentin8:auth");
        assert_eq!(
            normalize_service_type("test-payments-worker"),
            "test:payments:worker"
        );
        assert_eq!(normalize_service_type("sentin8-acme"), "sentin8:acme");
        assert_eq!(
            normalize_service_type("bank8-payments-worker"),
            "bank8:payments:worker"
        );
    }
}

/// The default Sentin8 service catalog.
///
/// Ports are NOT hardcoded in the catalog — Captain auto-assigns ports
/// sequentially starting from `SENTIN8_CAPTAIN_PORT_RANGE_LOW` (default
/// `sentin8::config::port_pool_low` = base+2) at reconcile time. The
/// `base_port` field in each entry is a hint for documentation only; the
/// actual port is the next free port in the global range. When scaling up
/// to a second instance, Captain picks the next available port globally
/// (not a per-service range).
///
/// `start_priority` tiers (lower starts first — see design ):
/// 0 = sentin8:captain (self-registered, never spawned)
/// 2 = acme (CA — must be Active before any service requests its cert)
/// 10 = auth (identity — the only issuer; domain-truth needs it live)
/// 15 = sys (domain-truth BEFORE any ingress: the proxy resolves tenant
///      hostnames via Sys's owner API `GET /v1/resolve/hostname`, and the
///      embedded sentin8-tls resolver in every service dials Sys through
///      the proxy ingress on cache miss — a tenant resolve against a
///      not-yet-started sys would degrade every tenant SNI in the boot
///      window; sys's own boot is fail-open — MemBus warm-up spawned,
///      DCR from the credential store, SSE consumer retries — so early
///      start with proxy/bus still down is safe)
/// 20 = proxy, bus (ingress transport + durable change-signals —
///      proxy's tenant-resolve misses now hit a LIVE sys; everything
///      downstream boots through a fully armed ingress)
/// 30 = storage, db, post, cron, stat, func, flow (middleware)
/// 40 = app (business)
/// 50 = bff, web (gateway, web apps)
///
/// Captain does NOT supervise DB (PostgreSQL), Valkey, or object storage
/// those are infrastructure and must be up before Captain starts.
/// The default Sentin8 service catalog (the platform's spawn truth — the
/// fleet placement values it carries are load-bearing, DESIGN §11.3).
///
/// Ports are NOT hardcoded in the catalog — Captain auto-assigns ports
/// sequentially starting from `SENTIN8_CAPTAIN_PORT_RANGE_LOW` at
/// reconcile time. When scaling to a second instance, Captain picks the
/// next available port globally (not a per-service range).
///
/// `start_priority` tiers (lower starts first): 0 captain, 2 acme,
/// 10 auth, 15 sys, 20 proxy/bus, 30 middleware, 40 app, 50 bff/web.
/// Captain does NOT supervise PostgreSQL, Valkey, or object storage —
/// those are infrastructure and must be up before Captain starts.
pub fn default_catalog() -> HashMap<String, ServiceCatalogEntry> {
    let mut m = HashMap::new();
    let mk = |service_type: &str, binary: &str, start_priority: i16| ServiceCatalogEntry {
        service_type: service_type.to_string(),
        binary: binary.to_string(),
        binary_path: String::new(),
        start_priority,
        fixed_port: 0,
        health_port: 0,
        use_http_health: false,
        upgrade_stop_first: false,
        extra_env: Default::default(),
        database_env_vars: Vec::new(),
        placement: String::new(),
        singleton: false,
        web_root: String::new(),
    };
    // Captain itself — not spawned by the catalog (it's already running),
    // but the monitor loop needs an entry so it samples captain's own
    // CPU/memory and updates the Valkey instance row. Without this,
    // `sentin8 captain services` shows 0.0 CPU / 0 MB for captain.
    m.insert(
        "sentin8:captain".into(),
        ServiceCatalogEntry {
            service_type: "sentin8:captain".into(),
            binary: "sentin8-captain".into(),
            binary_path: String::new(),
            start_priority: 0,
            fixed_port: sentin8::config::captain_port(),
            health_port: 0,
            use_http_health: true, // captain's /v1/health is plain HTTP
            upgrade_stop_first: false,
            extra_env: Default::default(),
            database_env_vars: Vec::new(),
            // One captain per machine is the machine lock's job; the
            // singleton flag mirrors it for the fleet view (§11.3).
            placement: String::new(),
            singleton: true,
            web_root: String::new(),
        },
    );
    // Tier 1 — ACME must be Active before any other service starts.
    m.insert(
        "sentin8:acme".into(),
        ServiceCatalogEntry {
            service_type: "sentin8:acme".into(),
            binary: "sentin8-acme".into(),
            binary_path: String::new(),
            start_priority: 2,
            fixed_port: 0,
            health_port: 0,
            use_http_health: false,
            upgrade_stop_first: false,
            extra_env: Default::default(),
            database_env_vars: Vec::new(),
            // FLEET-1 (DESIGN §11.3): the CA plane must never fork —
            // exactly one acme instance for the whole fleet. The placement
            // gate refuses any second spawn on any machine.
            placement: String::new(),
            singleton: true,
            web_root: String::new(),
        },
    );
    // Tier 2 — identity.
    m.insert(
        "sentin8:auth".into(),
        mk("sentin8:auth", "sentin8-auth", 10),
    );
    // Tier 2b — domain-truth BEFORE the ingress (proxy→sys startup
    // dependency): the proxy resolves tenant hostnames via Sys's owner
    // API and every service's embedded TLS resolver dials Sys through
    // the proxy on cache miss — sys must be Active before the ingress
    // arms. Sys's own boot is fail-open (MemBus warm-up spawned, store-
    // loaded DCR, SSE consumer retries), so proxy/bus being down is safe.
    m.insert("sentin8:sys".into(), mk("sentin8:sys", "sentin8-sys", 15));
    // Tier 3 — ingress transport + core messaging.
    m.insert(
        "sentin8:proxy".into(),
        ServiceCatalogEntry {
            service_type: "sentin8:proxy".into(),
            binary: "sentin8-proxy".into(),
            binary_path: String::new(),
            start_priority: 20,
            fixed_port: sentin8::config::sentin8_proxy_port(),
            health_port: 10000,    // proxy management API = local_port + 10000
            use_http_health: true, // proxy mgmt API is plain HTTP
            upgrade_stop_first: false,
            extra_env: Default::default(),
            database_env_vars: Vec::new(),
            // FLEET-1 (DESIGN §11.3): the ingress is pinned to the operator's
            // edge machine (`SENTIN8_CAPTAIN_EDGE_IP` on that host) and is a
            // fleet singleton — one :443 data plane.
            placement: "pin:edge".into(),
            singleton: true,
            web_root: String::new(),
        },
    );
    m.insert("sentin8:bus".into(), mk("sentin8:bus", "sentin8-bus", 20));
    // Tier 3 — platform middleware.
    m.insert(
        "sentin8:storage".into(),
        mk("sentin8:storage", "sentin8-storage", 30),
    );
    m.insert("sentin8:db".into(), mk("sentin8:db", "sentin8-db", 30));
    m.insert(
        "sentin8:post".into(),
        mk("sentin8:post", "sentin8-post", 30),
    );
    m.insert(
        "sentin8:cron".into(),
        mk("sentin8:cron", "sentin8-cron", 30),
    );
    m.insert(
        "sentin8:stat".into(),
        mk("sentin8:stat", "sentin8-stat", 30),
    );
    m.insert(
        "sentin8:func".into(),
        mk("sentin8:func", "sentin8-func", 30),
    );
    m.insert(
        "sentin8:flow".into(),
        mk("sentin8:flow", "sentin8-flow", 30),
    );
    m.insert("sentin8:ai".into(), mk("sentin8:ai", "sentin8-ai", 30));
    m.insert(
        "sentin8:secrets".into(),
        mk("sentin8:secrets", "sentin8-secrets", 30),
    );
    // Tier 4 — platform business services.
    m.insert("sentin8:app".into(), mk("sentin8:app", "sentin8-app", 40));
    // Tier 5 — BFF + web apps.
    m.insert("sentin8:bff".into(), mk("sentin8:bff", "sentin8-bff", 50));
    // Tier 6 — Flutter web apps (single instance serves all apps).
    m.insert("sentin8:web".into(), mk("sentin8:web", "sentin8-web", 50));
    m
}

