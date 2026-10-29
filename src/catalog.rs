// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Static service catalog - the *desired* definition of how to spawn each
//! service type. The live registry is `orch_services` (see `store.rs`);
//! the catalog is the bootstrap source.

/// One entry per service type Captain knows how to spawn.
///
/// Copied into the `orch_services.start_priority` column at insert time;
/// subsequent catalog changes require a migration to update existing rows.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// The servicecatalogentry type.
pub struct ServiceCatalogEntry {
    /// Which Sentin8 service this is (`bff`, `auth`, …). Matches the keys in
    /// TLS's `service_backends`.
    /// The service type.
    pub service_type: String,
    /// Binary name (cargo `--bin`) or path. Captain launches via
    /// `tokio::process::Command::new(binary)`.
    /// The binary.
    pub binary: String,
    /// Full resolved path to the binary (set at add-catalog time by
    /// searching SENTIN8_CAPTAIN_BINARY_PREFIX). When non-empty,
    /// spawn_command uses this directly instead of searching the
    /// global prefix. This allows each service to remember where its
    /// binary lives without a growing colon-separated env var.
    #[serde(default)]
    /// The binary path.
    pub binary_path: String,
    /// Startup ordering tier - lower starts first. Captain spawns services
    /// tier-by-tier with a 3-second pause between tiers and bounded
    /// concurrency within a tier.
    #[serde(default = "default_start_priority")]
    /// The start priority.
    pub start_priority: i16,
    /// When non-zero, the service always gets this fixed port (not
    /// auto-assigned from the global range). Used for services that must
    /// listen on a well-known port (e.g. proxy on 443).
    #[serde(default)]
    /// The fixed port.
    pub fixed_port: u16,
    /// Health-check port offset. When 0, the service's `local_port` is
    /// used for the health probe. When non-zero (e.g. 10000), the health
    /// probe targets `local_port + health_port` - this is how services
    /// with a separate management port (proxy, tls) are probed. The same
    /// offset is used to set `*_MGMT_PORT` env var when spawning.
    #[serde(default)]
    /// The health port.
    pub health_port: u16,
    /// When true, health probes use plain HTTP instead of HTTPS.
    /// Used by bootstrap services (acme) that serve HTTP because
    /// they must be reachable before TLS certs are provisioned.
    #[serde(default)]
    /// The use http health.
    pub use_http_health: bool,
    /// When true, `upgrade` stops the old instance BEFORE spawning the
    /// replacement (stop-first) instead of the rolling spawn-new→drain
    /// flow. Required for services whose process owns fixed secondary
    /// ports (e.g. an email MTA holding SMTP 25 or IMAP 143) - a
    /// rolling swap would collide on those ports while the old process
    /// is still draining.
    #[serde(default)]
    /// The upgrade stop first.
    pub upgrade_stop_first: bool,
    /// Extra environment variables passed to the spawned process
    /// (`{VAR: value}`). Vertical services use this to pin raw-protocol
    /// listener ports (e.g. `EMAIL8_MTA_SMTP_PORT: "25"`) so every
    /// instance of the service binds the same well-known ports.
    #[serde(default)]
    /// The extra env.
    pub extra_env: std::collections::HashMap<String, String>,
    /// Database-DSN environment-variable NAMES this service consumes
    /// (VDC §VDC.3, registry-driven propagation). Captain propagates the
    /// operator-set values of exactly these names from its own environment
    /// to the spawned process - values are never sourced from the catalog
    /// (secrets stay in the operator's env). Example for a vertical
    /// service: `["BANK8_LEDGER_DATABASE_URL", "BANK8_TLS_DATABASE_URL"]`.
    /// Platform `SENTIN8_*_DATABASE_URL` names are propagated
    /// unconditionally by the hardcoded allowlist; this field exists so
    /// vertical DSNs propagate WITHOUT hardcoding any vertical's name in
    /// captain (zero compile-time vertical knowledge).
    #[serde(default)]
    /// The database env vars.
    pub database_env_vars: Vec<String>,
    /// Web root directory for Flutter apps (relative to CWD).
    /// When non-empty, the service is treated as a Flutter web app
    /// and spawned via the static-server binary. This replaces `is_app`.
    #[serde(default)]
    /// The web root.
    pub web_root: String,
    /// Placement constraint (CAPT-3). Empty = unconstrained (spawns
    /// anywhere the scaler/upgrade flow chooses). `pin:{ip}` forces every
    /// instance of this service onto exactly one machine; `anti:{other}`
    /// forbids co-locating this service with the named service type on the
    /// same machine (the spawn path refuses and the scaler skips). Both are
    /// declarative catalog data - never runtime code. `pin:edge` is the
    /// operator-resolved pseudo-IP (`SENTIN8_CAPTAIN_EDGE_IP`, §11.3).
    #[serde(default)]
    /// The placement constraint.
    pub placement: String,
    /// Fleet singleton (DESIGN.md §11.3): at most ONE live instance of
    /// this service type anywhere in the fleet - the placement gate
    /// refuses any spawn (boot, start-services, scaler, remote spawn)
    /// when an Active instance exists on any machine. Used by services
    /// whose plane must not fork (acme - the CA; proxy - the ingress).
    #[serde(default)]
    /// The singleton placement flag.
    pub singleton: bool,
}

impl ServiceCatalogEntry {
    /// Parse the placement constraint. Returns `(kind, value)`:
    /// `PlacementKind::Pin` binds the service to one machine IP;
    /// `PlacementKind::AntiAffinity` forbids co-location with the value
    /// service type. `None` when unconstrained or malformed (malformed
    /// fails safe to unconstrained + a log at parse time).
    /// Handle parse placement.
    pub fn parse_placement(&self) -> Option<(PlacementKind, String)> {
        let raw = self.placement.trim();
        if raw.is_empty() {
            return None;
        }
        if let Some(ip) = raw.strip_prefix("pin:") {
            // A real machine IP (four dotted quads) OR the operator-resolved
            // `edge` pseudo-IP (DESIGN §11.3 - placement::resolve_pin maps
            // it via SENTIN8_CAPTAIN_EDGE_IP at spawn time).
            if (ip.split('.').count() == 4 && !ip.is_empty()) || ip == "edge" {
                return Some((PlacementKind::Pin, ip.to_string()));
            }
            return None;
        }
        if let Some(svc) = raw.strip_prefix("anti:") {
            if !svc.is_empty() {
                return Some((PlacementKind::AntiAffinity, svc.to_string()));
            }
            return None;
        }
        None
    }
}

/// Placement constraint kind (CAPT-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The placementkind type.
pub enum PlacementKind {
    /// Pin: every instance of the service must run on the given machine IP.
    /// The pin variant.
    Pin,
    /// Anti-affinity: the service must not share a machine with the given
    /// service type.
    /// The anti affinity variant.
    AntiAffinity,
}

// ── Constants (previously per-service fields, now global defaults) ──────

/// Health-check path (always `/v1/health` for all services).
/// The health path constant.
pub const HEALTH_PATH: &str = "/v1/health";
/// Health-check timeout in milliseconds.
/// The health timeout ms constant.
pub const HEALTH_TIMEOUT_MS: u64 = 15000;
/// Grace period (seconds) for SIGTERM → SIGKILL during stop/shutdown.
/// The grace period s constant.
pub const GRACE_PERIOD_S: u64 = 15;
/// Minimum instances to keep alive (scale-down never goes below this).
/// The min instances constant.
pub const MIN_INSTANCES: u8 = 1;
/// Maximum instances per service type per machine.
/// The max instances constant.
pub const MAX_INSTANCES: u8 = 1;

// ── Scaling thresholds (all "never scale" - auto-scaling is disabled) ───
/// The busy cpu pct constant.
pub const BUSY_CPU_PCT: f32 = 100.0;
/// The busy latency ms constant.
pub const BUSY_LATENCY_MS: f32 = 999999.0;
/// The busy window s constant.
pub const BUSY_WINDOW_S: u64 = 999999999;
/// The machine cpu cap pct constant.
pub const MACHINE_CPU_CAP_PCT: f32 = 100.0;
/// The machine mem cap pct constant.
pub const MACHINE_MEM_CAP_PCT: f32 = 100.0;
/// The idle cpu pct constant.
pub const IDLE_CPU_PCT: f32 = 0.0;
/// The idle latency ms constant.
pub const IDLE_LATENCY_MS: f32 = 999999.0;
/// The idle window s constant.
pub const IDLE_WINDOW_S: u64 = 999999999;

// ── Machine auto-provisioning ───
// The saturation detection (PROVISION_CPU_CAP_PCT / PROVISION_MEM_CAP_PCT)
// defaults are deliberately LOWER than the never-scale machine caps above:
// the scaler never fires with its pins, so `MACHINE_*_CAP` never
// saturates in practice. The provisioner needs a workable saturation
// threshold to be testable - like , provisioning is disabled by
// default (PROVISION_PROFILE defaults to Never), so re-enabling is a
// deliberate, reviewed change.

/// Saturation threshold: host CPU % at which a machine is considered
/// saturated. Lower than the never-scale
/// `MACHINE_CPU_CAP_PCT` pin so the signal is reachable.
/// The provision cpu cap pct constant.
pub const PROVISION_CPU_CAP_PCT: f32 = 95.0;
/// Saturation threshold: host memory % at which a machine is considered
/// saturated.
/// The provision mem cap pct constant.
pub const PROVISION_MEM_CAP_PCT: f32 = 95.0;
/// Sustained-saturation window (seconds) before a machine is provisioned
/// a transient spike must not trigger provisioning.
/// The provision window s constant.
pub const PROVISION_WINDOW_S: u64 = 60;
/// Cooldown (seconds) between machine provisions - at most one machine
/// per window, mirroring the one-instance-per-tick storm guard.
/// The provision cooldown s constant.
pub const PROVISION_COOLDOWN_S: u64 = 300;
/// Idle window (seconds) before a scale-in candidate machine is
/// deprovisioned.
/// The provision idle window s constant.
pub const PROVISION_IDLE_WINDOW_S: u64 = 600;
/// Idle thresholds for scale-in: a machine is idle when host CPU and mem
/// are both below these values for the idle window.
/// The provision idle cpu pct constant.
pub const PROVISION_IDLE_CPU_PCT: f32 = 5.0;
/// The provision idle mem pct constant.
pub const PROVISION_IDLE_MEM_PCT: f32 = 30.0;

fn default_start_priority() -> i16 {
    40
}

/// Derive the upper-snake env-var slug + worker flag for a service identity.
///
/// `(slug, is_worker)` where slug is the base identity in upper-snake form
/// (`bank8:payments:worker` → `("BANK8_PAYMENTS", true)`; `bank8:ledger` →
/// `("BANK8_LEDGER", false)`). The caller appends `_PORT` / `_W_PORT`.
fn port_env_parts(service_type: &str) -> (String, bool) {
    let base = sentin8::config::service_base_type(service_type);
    let is_worker = sentin8::config::is_worker_service(service_type);
    let slug = base.replace([':', '-'], "_").to_uppercase();
    (slug, is_worker)
}

impl ServiceCatalogEntry {
    /// Build the full `tokio::process::Command` argv for an instance on the
    /// given port. In dev we launch via `cargo run --bin <binary>` so the
    /// freshly built binary is used; in release (when
    /// `SENTIN8_CAPTAIN_BINARY_PREFIX` points at a bin dir) we exec the binary
    /// directly.
    /// Spawn command.
    pub fn spawn_command(&self, local_port: u16) -> tokio::process::Command {
        // Flutter web apps: spawn the Rust static-server binary, which
        // terminates TLS via sentin8-tls and serves the web build - so proxy
        // can pipe raw TLS to it like any Rust service (no L7 proxying).
        // Detected by non-empty web_root (replaces the old is_app flag).
        if !self.web_root.is_empty() {
            let web_root = &self.web_root;
            let prefix = std::env::var("SENTIN8_CAPTAIN_BINARY_PREFIX").ok();
            let mut c = if let Some(dir) = prefix {
                let path = std::path::Path::new(&dir).join("sentin8-web");
                tokio::process::Command::new(path)
            } else {
                let mut c = tokio::process::Command::new("cargo");
                c.arg("run").arg("--quiet").arg("--bin").arg("sentin8-web");
                c
            };
            c.arg("--web-root")
                .arg(web_root)
                .arg("--port")
                .arg(local_port.to_string());
            // Pass the compile-time build hash so the static server reports
            // the same build as captain without shelling out to git at runtime.
            return c;
        }

        // If this entry has a resolved binary_path (set by add-catalog),
        // use it directly - no need to search the global prefix.
        if !self.binary_path.is_empty() {
            let c = tokio::process::Command::new(&self.binary_path);
            // Fall through to env/args setup below.
            let mut cmd = c;
            // Set the service port env var.
            let (svc_upper, is_worker) = port_env_parts(&self.service_type);
            let port_env = if is_worker {
                format!("{}_W_PORT", svc_upper)
            } else {
                format!("{}_PORT", svc_upper)
            };
            cmd.env(port_env, local_port.to_string());
            if self.health_port > 0 {
                let mgmt_port = local_port + self.health_port;
                let mgmt_env = format!("{}_MGMT_PORT", svc_upper);
                cmd.env(mgmt_env, mgmt_port.to_string());
            }
            // Catalog-declared extra env (raw-protocol listener ports,
            // feature flags). Catalog values never override platform env.
            for (k, v) in &self.extra_env {
                cmd.env(k, v);
            }
            // VDC §VDC.3: catalog-declared database-DSN env-var names. Captain
            // propagates the operator-set values of these names so vertical DSNs
            // (e.g. BANK8_LEDGER_DATABASE_URL) reach the service without any
            // vertical name being hardcoded in captain.
            for key in &self.database_env_vars {
                if let Ok(val) = std::env::var(key) {
                    if !val.trim().is_empty() {
                        cmd.env(key, val);
                    }
                }
            }
            // Environment propagation.
            for key in [
                "SENTIN8_DOMAIN",
                "DATABASE_URL",
                // Per-service DSNs (DBX-CLI-6) - see the other spawn branch.
                "SENTIN8_AUTH_DATABASE_URL",
                "SENTIN8_SYS_DATABASE_URL",
                "SENTIN8_BUS_DATABASE_URL",
                "SENTIN8_POST_DATABASE_URL",
                "SENTIN8_STAT_DATABASE_URL",
                "SENTIN8_DB_DATABASE_URL",
                "SENTIN8_FUNC_DATABASE_URL",
                "SENTIN8_CRON_DATABASE_URL",
                "SENTIN8_FLOW_DATABASE_URL",
                "SENTIN8_STORAGE_DATABASE_URL",
                "SENTIN8_SECRETS_DATABASE_URL",
                "SENTIN8_APP_DATABASE_URL",
                "SENTIN8_AI_DATABASE_URL",
                "SENTIN8_TLS_DATABASE_URL",
                "SENTIN8_BFF_DATABASE_URL",
                "VALKEY_URL",
                // (group DESIGN.md §3.1): propagate the
                // plane's COORDINATES - services derive their Valkey URLs
                // (valkeys://{host}:{port}/0) or honor an explicit per-service
                // override from database_env_vars/extra_env. The historical
                // per-service VALKEY_URL propagation retired with the
                // logical-DB convention (the /N suffix was inert - GLIDE
                // connects at DB 0; ACL namespaces isolate).
                "SENTIN8_VALKEY_HOST",
                "SENTIN8_VALKEY_PORT",
                "SENTIN8_AUTH_ISSUER",
                "SENTIN8_AUTH_JWKS_URL",
                "SENTIN8_BUS_URL",
                // Certificate-bound M2M identity (auth design target
                // state). ONLY the public Root-CA PEM travels - NEVER
                // SENTIN8_ACME_DATA_DIR / _BASE_URL: the Acme data dir holds
                // the Root/Intermediate CA PRIVATE keys, and putting the dir
                // path into every service's env would let any compromised
                // service read them and forge the entire platform identity
                // chain (defeats the DCR cert gate). Workloads reach Acme's
                // public APIs over HTTPS (ServiceDiscovery), never its files.
                "SENTIN8_TLS_CLIENT_CA_PEM",
                "SENTIN8_TLS_CA_PEM",
                "SENTIN8_BASE_PORT",
                "SENTIN8_CAPTAIN_LOCAL_IP",
                "SENTIN8_AUTH_UI_DIR",
                // the platform-plane label map for the
                // database-free hostname resolver (static platform
                // hostnames - see crates/tls context.rs). Propagated from
                // the operator/captain environment; nothing
                // vertical-specific is hardcoded in the platform.
                "SENTIN8_TLS_PLATFORM_LABELS",
                // Per-deployment pool sizing (pg_pool): the
                // identity-invalidation fanout makes every service's policy
                // check refetch live identity over HTTP while holding a pool
                // connection; with the 3-conn default the platform-plane
                // services starve (8s acquire timeout → 500). Incident
                // run 28.
                "SENTIN8_PG_POOL_MAX",
            ] {
                if let Ok(val) = std::env::var(key) {
                    cmd.env(key, val);
                }
            }
            // Bootstrap enrollment credential ( target state): the
            // captain-brokered, time-boxed, encrypted-at-rest secret that
            // closes the first-boot chicken-and-egg - a workload with no
            // cert and no token cannot self-authenticate to acme, so acme
            // admits enrollment mints presenting the SAME secret captain
            // shared with it (verified locally, no auth round-trip).
            if let Ok((secret, ts)) = crate::bootstrap::ensure_enrollment() {
                cmd.env(crate::bootstrap::ENV_ENROLLMENT, &secret);
                cmd.env(crate::bootstrap::ENV_ENROLLMENT_TS, ts.to_string());
                // The captain's OWN policy/bus DCR loops also ride the
                // enrollment channel - seed this process's env too (idempotent
                // first-write; refreshes the TS copy when captain re-stamps).
                if std::env::var(crate::bootstrap::ENV_ENROLLMENT)
                    .map(|v| v.is_empty())
                    .unwrap_or(true)
                {
                    // SAFETY: boot/spawn path, single-threaded window.
                    std::env::set_var(crate::bootstrap::ENV_ENROLLMENT, &secret);
                    std::env::set_var(crate::bootstrap::ENV_ENROLLMENT_TS, ts.to_string());
                }
            }
            // Log redirect - FHS: /var/log/sentin8 (dev: .run/logs).
            let log_dir = sentin8::config::log_dir();
            let stdout_path =
                std::path::Path::new(&log_dir).join(format!("{}.log", self.service_type));
            if let Ok(file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&stdout_path)
            {
                cmd.stdout(std::process::Stdio::from(file));
            } else {
                cmd.stdout(std::process::Stdio::null());
            }
            if let Ok(file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&stdout_path)
            {
                cmd.stderr(std::process::Stdio::from(file));
            } else {
                cmd.stderr(std::process::Stdio::null());
            }
            cmd.stdin(std::process::Stdio::null());
            #[cfg(unix)]
            cmd.process_group(0);
            return cmd;
        }

        let prefix = std::env::var("SENTIN8_CAPTAIN_BINARY_PREFIX").ok();
        let mut cmd = if let Some(dirs) = prefix {
            // Release: exec the binary directly from `dir/<binary>`.
            // Supports colon-separated prefixes (e.g.
            // `sentin8/target/release:bank8/target/release:hotel8/target/release`)
            // so captain can find binaries from multiple Cargo workspaces.
            let binary_path = dirs
                .split(':')
                .map(|d| std::path::Path::new(d).join(&self.binary))
                .find(|p| p.is_file())
                .unwrap_or_else(|| {
                    // Fallback: first prefix dir (will fail with a clear error).
                    std::path::Path::new(dirs.split(':').next().unwrap_or("")).join(&self.binary)
                });

            tokio::process::Command::new(binary_path)
        } else {
            // Dev: `cargo run --quiet --bin <binary>`.
            let mut c = tokio::process::Command::new("cargo");
            c.arg("run").arg("--quiet").arg("--bin").arg(&self.binary);
            c
        };
        // Set the service port env var (e.g. SENTIN8_AUTH_PORT=3124). Workers
        // get a *_W_PORT env var (e.g. BANK8_PAYMENTS_W_PORT=8024) - the
        // worker binary reads this to bind its /v1/health endpoint.
        //
        // The env var name is derived from the service_type (colon identity,
        // ) by dropping the `:worker` segment
        // and mapping separators to underscores:
        // "sentin8:auth" → "SENTIN8_AUTH_PORT"
        // "bank8:ledger" → "BANK8_LEDGER_PORT"
        // "bank8:payments:worker" → "BANK8_PAYMENTS_W_PORT"
        let (svc_upper, is_worker) = port_env_parts(&self.service_type);
        let port_env = if is_worker {
            format!("{}_W_PORT", svc_upper)
        } else {
            format!("{}_PORT", svc_upper)
        };
        cmd.env(port_env, local_port.to_string());
        // If the service has a management port offset (e.g. proxy, tls),
        // set the *_MGMT_PORT env var to local_port + offset.
        if self.health_port > 0 {
            let mgmt_port = local_port + self.health_port;
            let mgmt_env = format!("{}_MGMT_PORT", svc_upper);
            cmd.env(mgmt_env, mgmt_port.to_string());
        }
        // Catalog-declared extra env (raw-protocol listener ports,
        // feature flags). Catalog values never override platform env.
        // Applied on BOTH branches - vertical services registered via the
        // prefix search (no per-entry binary_path) must receive them too.
        for (k, v) in &self.extra_env {
            cmd.env(k, v);
        } // VDC §VDC.3: catalog-declared database-DSN env-var names - same
          // propagation as the binary_path branch (see the comment there).
        for key in &self.database_env_vars {
            if let Ok(val) = std::env::var(key) {
                if !val.trim().is_empty() {
                    cmd.env(key, val);
                }
            }
        }
        // ── Environment propagation ───────────────────────────────────
        // Captain propagates env vars to child services so they don't need
        // to load.env themselves. This includes infrastructure
        // connection strings (DATABASE_URL, VALKEY_URL), platform config
        // (SENTIN8_DOMAIN, SENTIN8_AUTH_ISSUER), and per-service Valkey DBs.
        for key in [
            "SENTIN8_DOMAIN",
            "DATABASE_URL",
            // Per-service DSNs (DBX-CLI-6): each service connects with its
            // OWN NOBYPASSRLS role + search_path ({svc}, [declared cross-
            // schemas,] public). Without these the services fall back to the
            // shared superuser DSN and unqualified table references resolve
            // against the wrong schemas at runtime.
            "SENTIN8_AUTH_DATABASE_URL",
            "SENTIN8_SYS_DATABASE_URL",
            "SENTIN8_BUS_DATABASE_URL",
            "SENTIN8_POST_DATABASE_URL",
            "SENTIN8_STAT_DATABASE_URL",
            "SENTIN8_DB_DATABASE_URL",
            "SENTIN8_FUNC_DATABASE_URL",
            "SENTIN8_CRON_DATABASE_URL",
            "SENTIN8_FLOW_DATABASE_URL",
            "SENTIN8_STORAGE_DATABASE_URL",
            "SENTIN8_SECRETS_DATABASE_URL",
            "SENTIN8_APP_DATABASE_URL",
            "SENTIN8_AI_DATABASE_URL",
            "SENTIN8_TLS_DATABASE_URL",
            "SENTIN8_BFF_DATABASE_URL",
            "VALKEY_URL",
            // plane coordinates (see the binary_path
            // branch comment) - the per-service Valkey URL propagation
            // retired with the inert logical-DB convention.
            "SENTIN8_VALKEY_HOST",
            "SENTIN8_VALKEY_PORT",
            "SENTIN8_AUTH_ISSUER",
            "SENTIN8_AUTH_JWKS_URL",
            "SENTIN8_BUS_URL",
            // Certificate-bound M2M identity (auth design target
            // state): the PUBLIC Acme Root-CA PEM enables optional client
            // auth on the service's own TLS listener
            // (`SENTIN8_TLS_CLIENT_CA_PEM`), CA-trusts the outbound
            // DCR/token channel AND the PostgreSQL certificate-identity
            // plane (`SENTIN8_TLS_CA_PEM`, group DESIGN.md §3.2 - the
            // pg_pool factory resolves the same chain file). ONLY the
            // public cert path propagates - NEVER SENTIN8_ACME_DATA_DIR /
            // _BASE_URL (the Acme data dir holds the CA PRIVATE keys; see
            // the rationale on the other spawn branch).
            "SENTIN8_TLS_CLIENT_CA_PEM",
            "SENTIN8_TLS_CA_PEM",
            // Peer service ports - auto-assigned by captain and propagated to
            // children so cross-service callers (e.g. sentin8-tls → acme)
            // know where to reach them without hardcoded port literals.
            // children so cross-service callers (e.g. sentin8-tls → acme)
            // know where to reach them without hardcoded port literals.
            // NOTE: SENTIN8_ACME_PORT is intentionally NOT propagated here - it
            // is set per-instance above via `port_env` (e.g. SENTIN8_ACME_PORT=8023
            // during a rolling upgrade). Propagating the parent's SENTIN8_ACME_PORT
            // would overwrite the per-instance port and cause the new
            // instance to try binding the old instance's port, crashing it.
            // Other services learn acme's port via ServiceDiscovery (Valkey),
            // not from this env var.
            // Base port so children can derive the full port layout.
            "SENTIN8_BASE_PORT",
            // Local IP - propagated so ACME can include it in its bootstrap
            // cert SAN list (clients connect via IP from ServiceDiscovery).
            "SENTIN8_CAPTAIN_LOCAL_IP",
            // Auth hosted UI directory (built Flutter web app).
            "SENTIN8_AUTH_UI_DIR",
            // Local secret-reference store root ( - secret
            // references only). Services resolve `sentin8-secrets://` URIs
            // against this dir (e.g. fdx provider tokens); without it they
            // default to /etc/sentin8/secrets which is unwritable in dev.
            "SENTIN8_SECRETS_DIR",
            // M2M DCR file-cache root (/ - the authoritative
            // DCR credential load path). Without a writable cache every boot
            // re-runs the full DCR dance ( cold-boot
            // storms + retry-window exhaustion). The CLI sets it from
            // SENTIN8_SECRETS_DIR when not explicitly configured.
            "SENTIN8_M2M_CREDENTIALS_DIR",
        ] {
            if let Ok(val) = std::env::var(key) {
                cmd.env(key, val);
            }
        }

        // Bootstrap enrollment credential ( target state) - see the
        // full rationale on the binary_path spawn branch above.
        if let Ok((secret, ts)) = crate::bootstrap::ensure_enrollment() {
            cmd.env(crate::bootstrap::ENV_ENROLLMENT, &secret);
            cmd.env(crate::bootstrap::ENV_ENROLLMENT_TS, ts.to_string());
        }

        // Propagate the compile-time build hash to all spawned processes
        // (Rust services, Flutter apps, workers) so each binary can report
        // it in its health endpoint without running `git` at runtime.

        // Redirect stdout/stderr so crash output
        // is visible for debugging. Files are appended to (not truncated)
        // so restart history is preserved.
        let log_dir = sentin8::config::log_dir();
        let stdout_path = std::path::Path::new(&log_dir).join(format!("{}.log", self.service_type));
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&stdout_path)
        {
            cmd.stdout(std::process::Stdio::from(file));
        } else {
            cmd.stdout(std::process::Stdio::null());
        }
        let stderr_path = std::path::Path::new(&log_dir).join(format!("{}.log", self.service_type));
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&stderr_path)
        {
            cmd.stderr(std::process::Stdio::from(file));
        } else {
            cmd.stderr(std::process::Stdio::null());
        }
        cmd.stdin(std::process::Stdio::null());

        // Put the child in its own process group so that killing captain
        // (SIGTERM/SIGKILL) does NOT propagate to managed services. Each
        // service survives independently - captain re-adopts them on
        // restart by scanning Valkey for existing PIDs.
        #[cfg(unix)]
        cmd.process_group(0);

        cmd
    }
}

#[cfg(test)]
mod tests {
    use super::port_env_parts;

    #[test]
    fn port_env_parts_colon_identity() {
        assert_eq!(
            port_env_parts("sentin8:auth"),
            ("SENTIN8_AUTH".to_string(), false)
        );
        assert_eq!(
            port_env_parts("bank8:ledger"),
            ("BANK8_LEDGER".to_string(), false)
        );
        assert_eq!(
            port_env_parts("bank8:payments:worker"),
            ("BANK8_PAYMENTS".to_string(), true)
        );
    }

    #[test]
    fn port_env_parts_legacy_hyphen() {
        assert_eq!(
            port_env_parts("sentin8-auth"),
            ("SENTIN8_AUTH".to_string(), false)
        );
        assert_eq!(
            port_env_parts("bank8-payments-worker"),
            ("BANK8_PAYMENTS".to_string(), true)
        );
    }
}
