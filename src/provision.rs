// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Machine auto-provisioning - the cluster-autoscaler role.
//!
//! A narrow, deliberate exception to the "one captain per machine, no leader
//! election" principle: exactly ONE captain instance fleet-wide holds the
//! provisioning role, elected via a Valkey advisory lock. The election governs
//! ONLY the provisioning decision loop - process supervision stays per-machine
//! and election-free .
//!
//! Scaling axes:
//! - Vertical (in-machine): the scaler adds instances up to
//! `MAX_INSTANCES` per service per machine.
//! - Horizontal (cross-machine): THIS module provisions a new machine when
//! a machine is saturated (host CPU/mem at caps) AND in-machine scaling
//! is exhausted (the busy service is at `MAX_INSTANCES`).
//!
//! The signal is REUSED, not invented: every captain already samples whole-host
//! CPU/mem each tick into `captain:host:{ip}` ( step 9). The monitor
//! annotates that entry with `saturated = true` when the host crosses the
//! saturation thresholds (PROVISION-1); this module reads the annotation.
//!
//! Environment profile : `never` (default - disabled) / `auto`
//! (provision up to `MAX_MACHINES` with cooldown + scale-in). There is NO
//! `manual` profile - dry-run is `auto` + the `noop` backend.
//!
//! Backends : pluggable behind [`Provisioner`]. Only `noop` is
//! implemented; it records the decision and alerts without provisioning.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use glide::AsyncCommands;

use crate::config::CaptainConfig;

/// Valkey key holding the fleet-wide autoscaler leader lock.
/// The autoscaler lock key constant.
pub const AUTOSCALER_LOCK_KEY: &str = "captain:autoscaler:lock";
/// Valkey key prefix holding the last machine-provision timestamp
/// (cooldown gate). Full key: `captain:provision:last`.
/// The last provision key constant.
pub const LAST_PROVISION_KEY: &str = "captain:provision:last";
/// Valkey key prefix holding per-machine deprovision timestamps (scale-in
/// cooldown). Full key: `captain:deprovision:{ip}`.
/// The last deprovision key prefix constant.
pub const LAST_DEPROVISION_KEY_PREFIX: &str = "captain:deprovision:";
/// Valkey LIST holding the machine provision order (oldest first). Real
/// backends RPUSH the new machine's IP on a successful `Provisioned`
/// outcome; the scale-in LIFO picker reads it to retire the
/// most-recently-provisioned machine first. Empty with the `noop` backend.
/// The provision order key constant.
pub const PROVISION_ORDER_KEY: &str = "captain:provision:order";
/// Valkey HASH of pending machine-provision/deprovision requests awaiting
/// operator approval under the `manual` profile. Field =
/// `{kind}:{trigger_ip}`, value = JSON `PendingRequest`.
/// The pending key constant.
pub const PENDING_KEY: &str = "captain:provision:pending";

// ── Environment profile ────────────────────────────────

/// Machine auto-provisioning profile. The default is `Auto` (with the
/// default `noop` backend, that is a dry-run - decisions are recorded, no
/// machine is ever created). `Never` disables the role entirely; `Manual`
/// requires operator approval before the backend executes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
/// The provisionprofile type.
pub enum ProvisionProfile {
    /// No provisioning. Saturation stays a log/alert line.
    /// The never variant.
    Never,
    /// (default) Auto-provision up to `MAX_MACHINES`, with cooldown +
    /// scale-in. With the default `noop` backend this is dry-run mode.
    #[default]
    /// The auto variant.
    Auto,
    /// Manual approval: saturation records a PENDING request (Valkey +
    /// structured alert) and nothing executes until an operator approves
    /// via `POST /v1/captain/autoscaler/approve` .
    /// The manual variant.
    Manual,
}

impl ProvisionProfile {
    /// Parse the `SENTIN8_CAPTAIN_PROVISION_PROFILE` value. Unset → `Auto`
    /// (the operational default); an unrecognized value fails safe to
    /// `Never` - re-enabling/disabling is a deliberate, reviewed change.
    /// Parse it.
    pub fn parse(s: Option<&str>) -> Self {
        match s.map(str::trim).map(str::to_ascii_lowercase).as_deref() {
            Some("manual") => Self::Manual,
            Some("never") => Self::Never,
            Some("auto") => Self::Auto,
            // Unset → operational default (auto; dry-run with noop backend).
            None => Self::Auto,
            // Unknown value → fail safe to the most conservative choice.
            Some(_) => Self::Never,
        }
    }

    /// Handle as str.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Never => "never",
            Self::Auto => "auto",
            Self::Manual => "manual",
        }
    }
}

// ── Host sample shape (mirrors the monitor's `captain:host:{ip}` payload) ─

/// One machine's host sample as read from `captain:host:{ip}`.
#[derive(Debug, Clone)]
/// The machinesample type.
pub struct MachineSample {
    /// The ip.
    pub ip: String,
    /// The cpu pct.
    pub cpu_pct: f32,
    /// The mem pct.
    pub mem_pct: f32,
    /// The used mb.
    pub used_mb: f32,
    /// The ts.
    pub ts: i64,
    /// Saturation annotation written by the monitor (PROVISION-1).
    /// The saturated.
    pub saturated: bool,
    /// Busy service type recorded with the saturation annotation.
    /// The saturated service.
    pub saturated_service: String,
}

impl MachineSample {
    /// Parse a `captain:host:{ip}` JSON payload. Missing fields default
    /// defensively (older annotations pre-PROVISION-1 have no `saturated`).
    /// Handle from JSON.
    pub fn from_json(ip: &str, json: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(json).ok()?;
        Some(Self {
            ip: ip.to_string(),
            cpu_pct: v.get("cpu_pct").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32,
            mem_pct: v.get("mem_pct").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32,
            used_mb: v.get("used_mb").and_then(|x| x.as_f64()).unwrap_or(0.0) as f32,
            ts: v.get("ts").and_then(|x| x.as_i64()).unwrap_or(0),
            saturated: v
                .get("saturated")
                .and_then(|x| x.as_bool())
                .unwrap_or(false),
            saturated_service: v
                .get("saturated_service")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string(),
        })
    }
}

// ── Pure decision seams (TEST-8 pattern - mirror TEST-2) ────────────────

/// Saturation decision seam: host CPU/mem at or above the saturation caps.
/// Handle is saturated.
pub fn is_saturated(cpu_pct: f32, mem_pct: f32) -> bool {
    cpu_pct >= crate::catalog::PROVISION_CPU_CAP_PCT
        || mem_pct >= crate::catalog::PROVISION_MEM_CAP_PCT
}

/// Scale-in decision seam: host CPU/mem strictly below both idle thresholds.
/// Handle is idle host.
pub fn is_idle_host(cpu_pct: f32, mem_pct: f32) -> bool {
    cpu_pct < crate::catalog::PROVISION_IDLE_CPU_PCT
        && mem_pct < crate::catalog::PROVISION_IDLE_MEM_PCT
}

/// Cooldown decision seam - pure so TEST-8 can pin the storm guard.
/// `since_last` = seconds elapsed since the last provision; provisioning is
/// allowed only when the cooldown has fully elapsed.
/// Handle provision cooldown elapsed.
pub fn provision_cooldown_elapsed(since_last_s: Option<u64>, cooldown_s: u64) -> bool {
    match since_last_s {
        None => true,
        Some(elapsed) => elapsed >= cooldown_s,
    }
}

/// Scale-in target seam: pick the most-recently-provisioned idle machine
/// (LIFO - the base machine is never retired). `provision_order` is the
/// machines in provision order (oldest first, from `PROVISION_ORDER_KEY`);
/// the LAST idle candidate is retired first. Returns `None` when no machine
/// is idle.
/// Handle scale in target.
pub fn scale_in_target(
    samples: &[MachineSample],
    provision_order: &[String],
) -> Option<MachineSample> {
    // Idle candidates, most-recently-provisioned first (reverse provision
    // order; unknown machines sort last).
    let mut candidates: Vec<&MachineSample> = samples
        .iter()
        .filter(|s| is_idle_host(s.cpu_pct, s.mem_pct))
        .collect();
    candidates.sort_by_key(|s| {
        provision_order
            .iter()
            .position(|ip| ip == &s.ip)
            .unwrap_or(usize::MAX)
    });
    candidates.last().map(|s| (*s).clone())
}

/// Track sustained saturation per machine and sustained idle per machine.
fn saturated_since() -> &'static Mutex<HashMap<String, Instant>> {
    static S: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}
fn idle_since() -> &'static Mutex<HashMap<String, Instant>> {
    static I: OnceLock<Mutex<HashMap<String, Instant>>> = OnceLock::new();
    I.get_or_init(|| Mutex::new(HashMap::new()))
}

// ── Provisioner backends ───────────────────────────────

/// Request to provision a new machine. The autoscaler fills this from the
/// saturation signal + catalog.
#[derive(Debug, Clone)]
/// Request body for provision.
pub struct ProvisionRequest {
    /// The saturated machine that triggered the request.
    /// The triggered by ip.
    pub triggered_by_ip: String,
    /// The service that is busy and at `MAX_INSTANCES` on the trigger machine.
    /// The busy service.
    pub busy_service: String,
}

/// A machine-provision or deprovision request awaiting operator approval
/// under the `manual` profile. Stored as JSON in the
/// `captain:provision:pending` Valkey HASH.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
/// Request body for pending.
pub struct PendingRequest {
    /// `provision` or `deprovision`.
    /// The kind.
    pub kind: String,
    /// Target machine: trigger machine for provision, candidate IP for
    /// deprovision.
    /// The ip.
    pub ip: String,
    /// Busy service that triggered a provision request ("" for deprovision).
    /// The busy service.
    pub busy_service: String,
    /// Unix timestamp when the request was recorded.
    /// The requested at.
    pub requested_at: i64,
}

/// Outcome of a provision attempt.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProvisionOutcome {
    /// A machine was provisioned; `bootstrap_cmd` is the command the
    /// backend ran (or would run) to bootstrap captain on the new
    /// machine, and `ip` is the new machine's address (RPUSHed onto the
    /// provision-order list).
    Provisioned {
        /// The bootstrap command for the new machine.
        bootstrap_cmd: String,
        /// The new machine's address.
        ip: String,
    },
    /// Dry-run: the decision was recorded (alert) but nothing was
    /// provisioned. This is the `noop` backend's outcome.
    DryRun {
        /// The would-be bootstrap command.
        bootstrap_cmd: String,
    },
    /// The backend could not provision (error message).
    Failed {
        /// The backend's error detail.
        error: String,
    },
}

/// Pluggable machine provisioner.
///
/// Every backend produces the same contract: a machine with the Sentin8
/// binaries installed plus a bootstrap command that starts captain on it
/// pointed at the shared Valkey registry. The moment the new machine's
/// captain registers its services, Sentin8:Proxy picks them up automatically
/// - no proxy change.
#[async_trait::async_trait]
pub trait Provisioner: Send + Sync {
    /// The backend's short name.
    fn name(&self) -> &'static str;
    /// Provision a machine and return the outcome.
    async fn provision(
        &self,
        req: &ProvisionRequest,
        config: &CaptainConfig,
    ) -> Result<ProvisionOutcome, anyhow::Error>;
    /// Tear a machine down (remove it from the fleet).
    async fn deprovision(&self, ip: &str) -> Result<(), anyhow::Error>;
}

/// The `noop` backend - dry-run.
///
/// Records what *would* be provisioned and emits a Post alert, without
/// provisioning anything. Flipping `SENTIN8_CAPTAIN_PROVISION_BACKEND` from
/// `noop` to a real backend turns dry-run into real provisioning.
/// The noopprovisioner type.
pub struct NoopProvisioner;

/// Build the captain bootstrap command for a new machine.
/// Handle bootstrap command.
pub fn bootstrap_command(local_ip: &str, config: &CaptainConfig) -> String {
    format!(
        "sentin8-cli captain start --local-ip={local_ip} \
         --valkey-url={} --catalog-paths={}",
        config.valkey_url,
        std::env::var("SENTIN8_CAPTAIN_CATALOG_PATHS").unwrap_or_default(),
    )
}

#[async_trait::async_trait]
impl Provisioner for NoopProvisioner {
    fn name(&self) -> &'static str {
        "noop"
    }

    async fn provision(
        &self,
        req: &ProvisionRequest,
        config: &CaptainConfig,
    ) -> Result<ProvisionOutcome, anyhow::Error> {
        // Dry-run alert: structured warn so the Log relay surfaces it.
        tracing::warn!(
            triggered_by = %req.triggered_by_ip,
            busy_service = %req.busy_service,
            profile = "auto",
            "captain.provision.dry_run: machine saturated and in-machine scaling \
             exhausted - would provision a new machine (backend=noop, no action)"
        );
        Ok(ProvisionOutcome::DryRun {
            bootstrap_cmd: bootstrap_command("UNPROVISIONED", config),
        })
    }

    async fn deprovision(&self, ip: &str) -> Result<(), anyhow::Error> {
        tracing::warn!(
            ip,
            "captain.deprovision.dry_run: machine idle beyond window - would \
             deprovision (backend=noop, no action)"
        );
        Ok(())
    }
}

/// Resolve the configured backend by name. `noop` is the dry-run backend;
/// `cloud` / `hypervisor` / `bare-metal` / `docker` ALL execute **OpenTofu**
/// (`tofu apply`) against a per-backend module directory (design
/// one provisioning pipeline, four variable sets; `docker` uses the
/// `kreuzwerker/docker` provider with a macvlan network so each container
/// gets its own LAN IP). Unknown names fail safe to `noop` with a warning
/// so a typo never blocks the decision loop.
/// Resolve provisioner.
pub fn resolve_provisioner(name: &str) -> Box<dyn Provisioner> {
    match name.trim().to_ascii_lowercase().as_str() {
        "noop" => Box::new(NoopProvisioner),
        "cloud" | "hypervisor" | "bare-metal" | "docker" => Box::new(TofuProvisioner::new(name)),
        other => {
            tracing::warn!(
                backend = other,
                "unknown provision backend - falling back to noop"
            );
            Box::new(NoopProvisioner)
        }
    }
}

// ── OpenTofu backend ─────────────────────

/// The OpenTofu backend - one `tofu` pipeline for ALL FOUR environments
/// (`cloud` / `hypervisor` / `bare-metal` / `docker`).
///
/// Layout (all env vars, nothing hardcoded - consistent with the platform's
/// runtime-derivation discipline):
///
/// - `SENTIN8_CAPTAIN_TOFU_DIR` - working dir holding the OpenTofu
///   configuration (default `<state_dir/captain>/tofu`). The operator
///   supplies the `.tf` files (module per backend, variables below).
/// - `SENTIN8_CAPTAIN_TOFU_BIN` - binary name (default `tofu`).
///
/// Per-apply variables (passed as `-var`, never written to disk):
/// - `backend` = `cloud` | `hypervisor` | `bare-metal` | `docker`
/// - `action` = `provision` | `deprovision`
/// - `trigger_ip`, `busy_service`, `target_ip` - from the request
/// - `valkey_url`, `catalog_paths` - the bootstrap contract
///
/// The operator's `.tf` maps these onto the real provider (AWS/Azure/GCP,
/// Proxmox/vSphere, MAAS/Tinkerbell/IPMI, `kreuzwerker/docker`).
///
/// **Bootstrap contract - the module owns the full machine bring-up:**
/// install the sentin8 `.deb` (golden image / cloud-init / container
/// entrypoint - packaging design) and start captain connected to the
/// shared Valkey registry (the variables carry the contract to the
/// module). Rust never SSHes. After `apply`, the module MUST expose
/// `output "new_ip"` with the new machine's (or container's) IP; for
/// `deprovision` it destroys the target's resource.
///
/// **Container-fleet caveat (`docker`)**: `/proc/stat` and `/proc/meminfo`
/// are NOT namespaced - every container's `captain:host:{ip}` reports
/// host-level CPU/mem, so all sibling containers saturate simultaneously.
/// The cooldown + one-machine-per-window guard is what prevents a burst;
/// plan capacity accordingly (macvlan network is required so each
/// container gets its own LAN IP for the Valkey registry model).
///
/// Credentials are the provider's own env vars (AWS_ACCESS_KEY_ID,
/// PROXMOX_VE_API_TOKEN, …) - never stored by Sentin8 (secrets-by-reference).
/// The tofuprovisioner type.
pub struct TofuProvisioner {
    backend: String,
}

impl TofuProvisioner {
    /// Handle new.
    pub fn new(backend: &str) -> Self {
        Self {
            backend: backend.to_string(),
        }
    }

    fn tofu_dir(&self) -> String {
        std::env::var("SENTIN8_CAPTAIN_TOFU_DIR")
            .unwrap_or_else(|_| format!("{}/tofu", sentin8::config::captain_state_dir()))
    }

    fn tofu_bin(&self) -> String {
        std::env::var("SENTIN8_CAPTAIN_TOFU_BIN").unwrap_or_else(|_| "tofu".to_string())
    }

    /// Run `tofu apply -auto-approve -var...` in the module dir and return
    /// the parsed `new_ip` output (empty for deprovision).
    async fn run_apply(
        &self,
        action: &str,
        vars: &[(&str, String)],
    ) -> Result<String, anyhow::Error> {
        let dir = self.tofu_dir();
        let bin = self.tofu_bin();
        if !std::path::Path::new(&dir).join("main.tf").exists()
            && std::fs::read_dir(&dir)
                .map(|mut d| d.next().is_none())
                .unwrap_or(true)
        {
            anyhow::bail!(
                "OpenTofu module dir {dir} is empty - supply the .tf module for backend '{}'",
                self.backend
            );
        }
        let mut cmd = tokio::process::Command::new(&bin);
        cmd.current_dir(&dir)
            .arg("apply")
            .arg("-auto-approve")
            .arg("-input=false")
            .arg("-no-color");
        for (k, v) in vars {
            cmd.arg("-var").arg(format!("{k}={v}"));
        }
        cmd.stdin(std::process::Stdio::null());
        let out = cmd.output().await.map_err(|e| {
            anyhow::anyhow!("failed to exec {bin} (installed? `tofu -version`): {e}")
        })?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            let stdout = String::from_utf8_lossy(&out.stdout);
            anyhow::bail!(
                "tofu apply ({action}) failed ({}): {}{}",
                out.status,
                stdout.lines().last().unwrap_or(""),
                stderr.lines().last().unwrap_or("")
            );
        }
        if action == "deprovision" {
            return Ok(String::new());
        }
        // Contract: the module exposes the new machine's IP as output `new_ip`.
        let outp = tokio::process::Command::new(&bin)
            .current_dir(&dir)
            .args(["output", "-raw", "new_ip"])
            .output()
            .await?;
        if !outp.status.success() {
            anyhow::bail!(
                "tofu output new_ip failed ({}): {}",
                outp.status,
                String::from_utf8_lossy(&outp.stderr)
                    .lines()
                    .last()
                    .unwrap_or("")
            );
        }
        let ip = String::from_utf8_lossy(&outp.stdout).trim().to_string();
        if ip.is_empty() {
            anyhow::bail!("tofu output new_ip is empty - module must expose `output \"new_ip\"`");
        }
        Ok(ip)
    }
}

#[async_trait::async_trait]
impl Provisioner for TofuProvisioner {
    fn name(&self) -> &'static str {
        match self.backend.as_str() {
            "cloud" => "cloud",
            "hypervisor" => "hypervisor",
            "docker" => "docker",
            _ => "bare-metal",
        }
    }

    async fn provision(
        &self,
        req: &ProvisionRequest,
        config: &CaptainConfig,
    ) -> Result<ProvisionOutcome, anyhow::Error> {
        let valkey_url = config.valkey_url.clone();
        let catalog_paths = std::env::var("SENTIN8_CAPTAIN_CATALOG_PATHS").unwrap_or_default();
        tracing::info!(
            backend = %self.backend,
            triggered_by = %req.triggered_by_ip,
            busy_service = %req.busy_service,
            "tofu: applying provision (OpenTofu)"
        );
        // (DESIGN §11.5): the operator env contract - the module
        // materializes `sentin8_env_file`'s content as the machine's
        // /etc/sentin8/sentin8.env (the systemd unit sources it). The
        // content travels as a file var (sensitive), never logged; the
        // operator composes it once per deployment. `edge_ip` is set ONLY
        // when provisioning the edge machine (the proxy's `pin:edge`
        // resolves against SENTIN8_CAPTAIN_EDGE_IP inside that machine).
        let env_file = std::env::var("SENTIN8_CAPTAIN_MACHINE_ENV_FILE").unwrap_or_default();
        let edge_ip = std::env::var("SENTIN8_CAPTAIN_EDGE_IP").unwrap_or_default();
        let mut vars = vec![
            ("backend", self.backend.clone()),
            ("action", "provision".to_string()),
            ("trigger_ip", req.triggered_by_ip.clone()),
            ("busy_service", req.busy_service.clone()),
            ("target_ip", String::new()),
            ("valkey_url", valkey_url.clone()),
            ("catalog_paths", catalog_paths.clone()),
        ];
        if !env_file.is_empty() {
            vars.push(("sentin8_env_file", format!("@{env_file}")));
        }
        if !edge_ip.is_empty() {
            vars.push(("edge_ip", edge_ip.clone()));
        }
        let new_ip = match self.run_apply("provision", &vars).await {
            Ok(ip) => ip,
            // The OpenTofu apply itself failed - surface as a structured
            // outcome (the decision loop logs it; no machine was created).
            Err(e) => {
                tracing::error!(backend = %self.backend, error = %e, "tofu: provision apply failed");
                return Ok(ProvisionOutcome::Failed {
                    error: e.to_string(),
                });
            }
        };
        // Bootstrap contract : the MODULE owns the full machine
        // bring-up - install the sentin8 `.deb` (golden image / cloud-init,
        // packaging design) and start captain pointed at the shared Valkey
        // registry (the variables above carry the bootstrap contract to the
        // module; cloud-init, container entrypoint, or MAAS deploy scripts
        // consume it). Rust never SSHes - that kept the backend boundary
        // clean and made `docker` (no sshd) a valid backend. Proxy picks
        // the new machine's services up automatically from the registry.
        let bootstrap = bootstrap_command(&new_ip, config);
        tracing::info!(
            ip = %new_ip,
            backend = %self.backend,
            bootstrap = %bootstrap,
            "tofu: machine provisioned - module contract: captain running + Valkey-connected"
        );
        // Post-provision sanity: the machine should appear in the registry
        // shortly. We do NOT block - the next monitor tick's host-sample
        // scan picks it up (2-min TTL on `captain:host:{ip}`), and the
        // provision-order list already got the IP for LIFO scale-in.
        Ok(ProvisionOutcome::Provisioned {
            bootstrap_cmd: bootstrap,
            ip: new_ip,
        })
    }

    async fn deprovision(&self, ip: &str) -> Result<(), anyhow::Error> {
        tracing::info!(ip, backend = %self.backend, "tofu: applying deprovision");
        // (DESIGN §11.5): graceful leave FIRST - best-effort call to
        // the target captain's /v1/captain/shutdown so services stop and
        // registry rows delete before the machine is destroyed. A
        // machine that cannot be reached is destroyed anyway (its rows
        // age out via the host-sample/enrollment TTLs).
        if let Err(e) = graceful_leave(ip).await {
            tracing::warn!(
                ip,
                error = %e,
                "tofu: graceful leave failed - destroying anyway (rows expire by TTL)"
            );
        }
        let vars = [
            ("backend", self.backend.clone()),
            ("action", "deprovision".to_string()),
            ("trigger_ip", String::new()),
            ("busy_service", String::new()),
            ("target_ip", ip.to_string()),
            ("valkey_url", String::new()),
            ("catalog_paths", String::new()),
        ];
        self.run_apply("deprovision", &vars).await?;
        tracing::info!(ip, "tofu: machine deprovisioned");
        Ok(())
    }
}

/// Ask the machine at `ip` to leave the fleet gracefully (
/// DESIGN §11.5): `POST /v1/captain/shutdown` on its captain stops its
/// services, deletes its registry rows, and clears its enrollment record -
/// a clean exit instead of a destroyed machine's stale entries.
///
/// Best-effort with a 10s cap: unreachable or refused machines return
/// `Err` and the caller destroys anyway. The call is unauthenticated by
/// design - the machine lock guarantees exactly one captain per IP and
/// only the operator plane (or the destruction path) knows fleet
/// membership; a wrong-machine call shuts down a machine the caller
/// already owns the lifecycle decision for.
async fn graceful_leave(ip: &str) -> Result<(), anyhow::Error> {
    let url = format!(
        "http://{ip}:{}/v1/captain/shutdown",
        sentin8::config::captain_port()
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;
    let resp = client
        .post(&url)
        .json(&serde_json::json!({}))
        .send()
        .await?;
    if !resp.status().is_success() {
        anyhow::bail!("shutdown endpoint returned {}", resp.status());
    }
    Ok(())
}

// ── Remote spawn (DESIGN §11.4) ────────────────────────

/// Candidate machine for the remote-spawn selection seam.
#[derive(Debug, Clone)]
pub struct MachineCandidate {
    /// The machine IP.
    pub ip: String,
    /// Host CPU% (cgroup- or /proc-sourced - the telemetry mode decides).
    pub cpu_pct: f32,
    /// Host MEM%.
    pub mem_pct: f32,
}

/// Pure selection seam: rank machines that ADMIT the service (placement
/// checked by the caller against each machine's instances) by load -
/// lowest combined (cpu+mem) first, this machine excluded (the leader
/// spawns on its own machine through the normal local path; a
/// leader-tries-leader call would be a same-machine retry of a decision
/// that already said "not here").
/// Handle select target machine.
pub fn select_target_machine(
    candidates: &[MachineCandidate],
    exclude_ip: &str,
) -> Option<MachineCandidate> {
    candidates
        .iter()
        .filter(|m| m.ip != exclude_ip)
        .min_by(|a, b| {
            (a.cpu_pct + a.mem_pct)
                .partial_cmp(&(b.cpu_pct + b.mem_pct))
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .cloned()
}

/// Remotely spawn `service_type` on the chosen machine (
/// DESIGN §11.4): `POST /v1/captain/instances` on the target captain with
/// the cert-bound `captain-remote` M2M workload's token
/// (`sentin8:captain:instances:write`).
///
/// The target's placement gate is the authority - a 409 means the machine
/// it refuses (pin elsewhere, anti violation, singleton twin) and the
/// caller records the alert and moves on. Transport failures are `Err`
/// (retry next tick under the normal cooldown rules).
pub async fn remote_spawn(
    target_ip: &str,
    service_type: &str,
) -> Result<Vec<String>, anyhow::Error> {
    // auth DESIGN §4.3f: the `captain-remote` CERTIFICATE is
    // the identity - presented on the TLS handshake of the remote
    // captain call; the target's TLS layer authenticates it and the
    // registry map authorizes `sentin8:captain:instances:write`.
    let issuer = sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer();
    let ca_path = sentin8::auth::m2m::platform_ca_path();
    let cert = sentin8::auth::m2m::ensure_workload_certificate(&issuer, "captain-remote", &ca_path)
        .await?;
    let mtls = sentin8::middleware::mtls::MtlsConfig::new(
        &cert.ca_cert_path,
        &cert.cert_path,
        &cert.key_path,
    );
    let client = sentin8::middleware::mtls::build_mtls_client(&mtls)
        .map_err(|e| anyhow::anyhow!("captain-remote transport: {e}"))?;
    let url = format!(
        "http://{target_ip}:{}/v1/captain/instances",
        sentin8::config::captain_port()
    );
    let resp = client
        .post(&url)
        .json(&serde_json::json!({"service_types": [service_type]}))
        .send()
        .await?;
    let status = resp.status();
    if status.as_u16() == 409 {
        anyhow::bail!("target refused by its placement gate (409)");
    }
    if !status.is_success() {
        anyhow::bail!("remote spawn returned {status}");
    }
    let body: serde_json::Value = resp.json().await?;
    let started = body
        .get("started_services")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Ok(started)
}

/// Extracted tail call: `evaluate`'s scale-out half found the pressure
/// already placed (remote spawn) - run only the scale-in half
/// with the tick's machine list. Mirrors `scale_in`'s contract.
async fn skip_to_scale_in(
    conn: &glide::GlideClient,
    config: &CaptainConfig,
    machines: Vec<MachineSample>,
    fleet: usize,
) -> Result<(), anyhow::Error> {
    scale_in(conn, config, machines, fleet).await
}

// ── Leader election ────────────────────────────────────

/// Try to acquire the fleet-wide autoscaler lock (30s TTL, heartbeated every
/// tick while held). Returns true when this captain is the autoscaler leader.
/// Handle try acquire leader lock.
pub async fn try_acquire_leader_lock(conn: &glide::GlideClient) -> Result<bool, glide::GlideError> {
    let result: Option<String> = glide::cmd("SET")
        .arg(AUTOSCALER_LOCK_KEY)
        .arg(std::process::id().to_string())
        .arg("NX")
        .arg("EX")
        .arg(30)
        .query_async(conn)
        .await?;
    Ok(result.is_some())
}

/// Release the autoscaler leader lock (graceful shutdown).
/// Handle release leader lock.
pub async fn release_leader_lock(conn: &glide::GlideClient) -> Result<(), glide::GlideError> {
    let _: () = conn.del(AUTOSCALER_LOCK_KEY).await?;
    Ok(())
}

// ── The decision loop ──────────────────────────

/// Read all fresh `captain:host:{ip}` samples (the 2-minute TTL means a
/// machine whose captain died stops appearing - its samples expire).
/// List machines.
pub async fn list_machines(conn: &glide::GlideClient) -> Result<Vec<MachineSample>, anyhow::Error> {
    let keys: Vec<String> = glide::cmd("KEYS")
        .arg("captain:host:*")
        .query_async(conn)
        .await?;
    let mut machines = Vec::new();
    for key in &keys {
        let val: Option<String> = glide::cmd("GET").arg(key).query_async(conn).await?;
        let Some(json) = val else { continue };
        let ip = key.strip_prefix("captain:host:").unwrap_or("");
        if let Some(sample) = MachineSample::from_json(ip, &json) {
            machines.push(sample);
        }
    }
    machines.sort_by(|a, b| a.ip.cmp(&b.ip));
    Ok(machines)
}

/// Count live machines in the fleet - the registry rows across ALL IPs
/// (host samples expire after 2 min; the registry is the fleet's ground
/// truth). Captain self-registers on every machine ( edge case 21).
/// Handle count fleet machines.
pub async fn count_fleet_machines(conn: &glide::GlideClient) -> Result<usize, anyhow::Error> {
    let keys: Vec<String> = glide::cmd("KEYS")
        .arg("captain:svc:sentin8:captain")
        .query_async(conn)
        .await?;
    let mut ips = std::collections::HashSet::new();
    for key in &keys {
        let entries: Vec<(String, String)> = conn.hgetall(key).await?;
        for (field, _json) in entries {
            // Field = `{ip}:{port}` - the IP is everything before the last colon.
            if let Some(ip) = field.rsplit_once(':').map(|(ip, _)| ip) {
                ips.insert(ip.to_string());
            }
        }
    }
    Ok(ips.len())
}

/// Read seconds since the last machine provision (cooldown gate).
async fn seconds_since_last_provision(
    conn: &glide::GlideClient,
) -> Result<Option<u64>, anyhow::Error> {
    let val: Option<String> = glide::cmd("GET")
        .arg(LAST_PROVISION_KEY)
        .query_async(conn)
        .await?;
    let Some(ts) = val.and_then(|s| s.parse::<i64>().ok()) else {
        return Ok(None);
    };
    let now = chrono::Utc::now().timestamp();
    Ok(Some((now - ts).max(0) as u64))
}

/// Record a provision (or dry-run decision) - starts the cooldown window.
async fn record_provision(conn: &glide::GlideClient) -> Result<(), anyhow::Error> {
    let _: () = glide::cmd("SET")
        .arg(LAST_PROVISION_KEY)
        .arg(chrono::Utc::now().timestamp().to_string())
        .query_async(conn)
        .await?;
    Ok(())
}

/// One autoscaler evaluation, run on every monitor tick by the elected
/// leader. Implements (scale-out) and (scale-in).
/// Handle evaluate.
pub async fn evaluate(
    conn: &glide::GlideClient,
    config: &CaptainConfig,
) -> Result<(), anyhow::Error> {
    // Profile gate first - `never` means the whole role is inert.
    if config.provision_profile == ProvisionProfile::Never {
        return Ok(());
    }

    // Renew the leader lock. If we lost it (another captain grabbed the
    // expired key), this tick is not ours to decide.
    let is_leader = try_acquire_leader_lock(conn).await?;
    if !is_leader {
        return Ok(());
    }

    let machines = list_machines(conn).await?;
    let fleet = machines.len();

    // ── Scale-out ─────────────────────────────────────────────
    // A machine saturated continuously for > window AND fleet headroom AND
    // cooldown elapsed → provision one machine. Under the `manual` profile
    // the request is RECORDED (Valkey + alert) instead of executed - an
    // operator approves via POST /v1/captain/autoscaler/approve.
    let mut provision_req: Option<ProvisionRequest> = None;
    for m in &machines {
        let saturated = is_saturated(m.cpu_pct, m.mem_pct) || m.saturated;
        {
            let mut ss = saturated_since().lock().unwrap();
            if saturated {
                ss.entry(m.ip.clone()).or_insert_with(Instant::now);
            } else {
                ss.remove(&m.ip);
            }
        }
        if !saturated || provision_req.is_some() {
            continue;
        }
        let sustained = {
            let ss = saturated_since().lock().unwrap();
            ss.get(&m.ip).map(|t| t.elapsed().as_secs()).unwrap_or(0)
                >= config.provision_window_s.max(1)
        };
        if !sustained {
            continue;
        }
        let since_last = seconds_since_last_provision(conn).await?;
        let cooldown_ok = provision_cooldown_elapsed(since_last, config.provision_cooldown_s);
        let headroom = (fleet as u32) < config.max_machines.max(1);
        // In-machine scaling must be exhausted first (/): the
        // busy service must already sit at MAX_INSTANCES on the trigger
        // machine - otherwise the scaler still has headroom to add an
        // instance locally and a new machine is premature. An unknown busy
        // service (older annotation / no Active instance) cannot be verified
        // and is treated as exhausted so the decision loop stays testable.
        let in_machine_exhausted = m.saturated_service.is_empty()
            || match crate::store::count_for_type_on_ip(conn, &m.saturated_service, &m.ip).await {
                Ok(count) => (count as u8) >= crate::catalog::MAX_INSTANCES,
                Err(_) => true,
            };
        if cooldown_ok && headroom && in_machine_exhausted {
            provision_req = Some(ProvisionRequest {
                triggered_by_ip: m.ip.clone(),
                busy_service: if m.saturated_service.is_empty() {
                    "unknown".to_string()
                } else {
                    m.saturated_service.clone()
                },
            });
        } else if !headroom {
            tracing::warn!(
                fleet,
                max_machines = config.max_machines,
                "captain.provision.at_cap: machine saturated but fleet is at MAX_MACHINES"
            );
        }
    }

    if let Some(req) = provision_req {
        // (DESIGN §11.4): before provisioning a NEW machine, try
        // placing the busy service on an EXISTING machine - remote spawn
        // first, provision second. The selection is placement- and
        // load-aware; a 409/transport failure falls through to the
        // provision path (the next tick retries under the normal cooldown
        // rules). This never runs under the `manual` profile (the approval
        // queue governs everything there).
        if config.provision_profile == ProvisionProfile::Auto
            && !config.provision_backend.is_empty()
            && config.provision_backend != "noop"
        {
            if let Some(target) = select_target_machine(
                &machines
                    .iter()
                    .map(|m| MachineCandidate {
                        ip: m.ip.clone(),
                        cpu_pct: m.cpu_pct,
                        mem_pct: m.mem_pct,
                    })
                    .collect::<Vec<_>>(),
                &req.triggered_by_ip,
            ) {
                match remote_spawn(&target.ip, &req.busy_service).await {
                    Ok(started) if !started.is_empty() => {
                        tracing::info!(
                            service = %req.busy_service,
                            target = %target.ip,
                            "autoscaler: remote spawn placed the service on an existing machine - no new machine needed"
                        );
                        let _ = record_provision(conn).await;
                        // Placed - the saturation pressure moves with it.
                        // Skip the provision decision this tick.
                        return skip_to_scale_in(conn, config, machines, fleet).await;
                    }
                    Ok(_) => {
                        // Started nothing (already running there / not in
                        // the target's catalog) - fall through to provision.
                    }
                    Err(e) => {
                        tracing::warn!(
                            service = %req.busy_service,
                            target = %target.ip,
                            error = %e,
                            "autoscaler: remote spawn failed - falling through to machine provision"
                        );
                    }
                }
            }
        }
        let provisioner = resolve_provisioner(&config.provision_backend);
        if config.provision_profile == ProvisionProfile::Manual {
            // Manual profile: record a pending request for operator approval
            // - nothing executes until POST /v1/captain/autoscaler/approve.
            let pending = PendingRequest {
                kind: "provision".into(),
                ip: req.triggered_by_ip.clone(),
                busy_service: req.busy_service.clone(),
                requested_at: chrono::Utc::now().timestamp(),
            };
            let field = format!("provision:{}", req.triggered_by_ip);
            let _: Result<(), glide::GlideError> = glide::cmd("HSET")
                .arg(PENDING_KEY)
                .arg(&field)
                .arg(serde_json::to_string(&pending).unwrap_or_default())
                .query_async(conn)
                .await;
            let _: Result<(), glide::GlideError> = glide::cmd("EXPIRE")
                .arg(PENDING_KEY)
                .arg(3600)
                .query_async(conn)
                .await;
            tracing::warn!(
                triggered_by = %req.triggered_by_ip,
                busy_service = %req.busy_service,
                "captain.provision.requested: manual profile - operator approval \
                 required (POST /v1/captain/autoscaler/approve)"
            );
            // The pending record starts the cooldown so the alert fires
            // once per window, not every tick.
            let _ = record_provision(conn).await;
        } else {
            match provisioner.provision(&req, config).await {
                Ok(outcome) => {
                    // A real backend that succeeded records the new machine's IP
                    // on the provision-order list (oldest first) so the scale-in
                    // LIFO picker can retire the newest machine first.
                    if let ProvisionOutcome::Provisioned { ip, .. } = &outcome {
                        let _: Result<(), glide::GlideError> = glide::cmd("RPUSH")
                            .arg(PROVISION_ORDER_KEY)
                            .arg(ip)
                            .query_async(conn)
                            .await;
                    }
                    tracing::info!(
                        triggered_by = %req.triggered_by_ip,
                        backend = provisioner.name(),
                        outcome = ?outcome,
                        "autoscaler: provision decision recorded"
                    );
                    // Even a dry-run starts the cooldown - otherwise noop mode
                    // would alert every tick after the window.
                    let _ = record_provision(conn).await;
                }
                Err(e) => tracing::error!(error = %e, "autoscaler: provision failed"),
            }
        }
    }

    // ── Scale-in ──────────────────────────────────────────────
    scale_in(conn, config, machines, fleet).await
}

/// The scale-in half of one autoscaler evaluation - extracted so the
/// remote-spawn placement path can skip the scale-out half
/// without duplicating the idle logic. Same invariants: at most one
/// machine per tick, LIFO never retires the base machine, cooldown is
/// shared with scale-out.
/// Handle scale in.
async fn scale_in(
    conn: &glide::GlideClient,
    config: &CaptainConfig,
    machines: Vec<MachineSample>,
    fleet: usize,
) -> Result<(), anyhow::Error> {
    if (fleet as u32) <= config.min_machines.max(1) {
        // At the floor - clear idle tracking so a later scale-out doesn't
        // inherit a stale "idle for 10 minutes" state.
        idle_since().lock().unwrap().clear();
        return Ok(());
    }
    // Idle candidates: sustained idle beyond the idle window. Deprovision at
    // most one machine per tick (same storm guard as scale-out).
    let target_ip: Option<String> = {
        let mut is = idle_since().lock().unwrap();
        is.retain(|ip, _| machines.iter().any(|m| &m.ip == ip));
        let mut target = None;
        for m in &machines {
            if is_idle_host(m.cpu_pct, m.mem_pct) {
                let since = is.entry(m.ip.clone()).or_insert_with(Instant::now);
                if since.elapsed().as_secs() >= config.provision_idle_window_s.max(1) {
                    target = Some(m.ip.clone());
                    break;
                }
            } else {
                is.remove(&m.ip);
            }
        }
        target
    };
    if let Some(ip) = target_ip {
        // LIFO seam: among sustained-idle machines, retire the
        // most-recently-provisioned one - the base machine is protected.
        // The sustained-idle set feeds the picker; when several machines
        // are idle beyond the window, `scale_in_target` orders them by
        // provision history (LIFO) so the newest machine leaves first.
        let order: Vec<String> = glide::cmd("LRANGE")
            .arg(PROVISION_ORDER_KEY)
            .arg(0)
            .arg(-1)
            .query_async(conn)
            .await
            .unwrap_or_default();
        let selected = match scale_in_target(
            &machines
                .iter()
                .filter(|m| is_idle_host(m.cpu_pct, m.mem_pct))
                .cloned()
                .collect::<Vec<_>>(),
            &order,
        ) {
            Some(t) => t.ip,
            None => ip.clone(),
        };
        // Scale-in cooldown: reuse the provision cooldown key family - a
        // deprovision also bumps it so scale-out and scale-in never fire in
        // the same window (fleet flapping guard).
        let since_last = seconds_since_last_provision(conn).await?;
        if !provision_cooldown_elapsed(since_last, config.provision_cooldown_s) {
            return Ok(());
        }
        let provisioner = resolve_provisioner(&config.provision_backend);
        if config.provision_profile == ProvisionProfile::Manual {
            // Manual profile: record a pending deprovision request.
            let pending = PendingRequest {
                kind: "deprovision".into(),
                ip: selected.clone(),
                busy_service: String::new(),
                requested_at: chrono::Utc::now().timestamp(),
            };
            let field = format!("deprovision:{selected}");
            let _: Result<(), glide::GlideError> = glide::cmd("HSET")
                .arg(PENDING_KEY)
                .arg(&field)
                .arg(serde_json::to_string(&pending).unwrap_or_default())
                .query_async(conn)
                .await;
            tracing::warn!(
                ip = %selected,
                "captain.deprovision.requested: manual profile - operator approval \
                 required (POST /v1/captain/autoscaler/approve)"
            );
            let _ = record_provision(conn).await;
            return Ok(());
        }
        match provisioner.deprovision(&selected).await {
            Ok(()) => {
                tracing::info!(ip = %selected, "autoscaler: scale-in decision recorded");
                let _: Result<(), glide::GlideError> = glide::cmd("SET")
                    .arg(format!("{LAST_DEPROVISION_KEY_PREFIX}{selected}"))
                    .arg(chrono::Utc::now().timestamp().to_string())
                    .query_async(conn)
                    .await;
                // Remove the machine from the provision-order list.
                let _: Result<usize, glide::GlideError> = glide::cmd("LREM")
                    .arg(PROVISION_ORDER_KEY)
                    .arg(1)
                    .arg(&selected)
                    .query_async(conn)
                    .await;
                let _ = record_provision(conn).await;
            }
            Err(e) => tracing::error!(ip = %selected, error = %e, "autoscaler: deprovision failed"),
        }
    }

    Ok(())
}

/// Called by the server on graceful shutdown to release the leader lock.
/// Handle shutdown cleanup.
pub async fn shutdown_cleanup(conn: &glide::GlideClient) {
    if let Err(e) = release_leader_lock(conn).await {
        tracing::warn!(error = %e, "failed to release autoscaler leader lock");
    }
}

// ── Manual-profile approval ────────────────────────────

/// List pending requests awaiting operator approval (`manual` profile).
/// Reads the `captain:provision:pending` HASH; expired entries are skipped.
/// List pending.
pub async fn list_pending(conn: &glide::GlideClient) -> Result<Vec<PendingRequest>, anyhow::Error> {
    let entries: Vec<(String, String)> = conn.hgetall(PENDING_KEY).await?;
    let mut pending = Vec::new();
    for (_field, json) in entries {
        if let Ok(p) = serde_json::from_str::<PendingRequest>(&json) {
            pending.push(p);
        }
    }
    pending.sort_by_key(|p| p.requested_at);
    Ok(pending)
}

/// Operator decision on a pending request: `approve` executes it through
/// the configured backend; `reject` discards it. Called from the
/// `POST /v1/captain/autoscaler/approve` handler (Shield-gated).
/// Approve it.
pub async fn approve(
    conn: &glide::GlideClient,
    config: &CaptainConfig,
    kind: &str,
    ip: &str,
    decision: &str,
) -> Result<serde_json::Value, anyhow::Error> {
    let field = format!("{kind}:{ip}");
    // Reject → drop the pending entry, nothing executes.
    if decision == "reject" {
        let _: () = conn.hdel(PENDING_KEY, &field).await?;
        tracing::info!(kind, ip, "provision request rejected by operator");
        return Ok(serde_json::json!({"status": "rejected", "kind": kind, "ip": ip}));
    }
    // Approve → fetch the pending record, clear it, execute the backend.
    let raw: Option<String> = conn.hget(PENDING_KEY, &field).await?;
    let record: PendingRequest = raw
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .ok_or_else(|| anyhow::anyhow!("no pending {kind} request for {ip}"))?;
    let _: () = conn.hdel(PENDING_KEY, &field).await?;
    let provisioner = resolve_provisioner(&config.provision_backend);
    if kind == "provision" {
        let req = ProvisionRequest {
            triggered_by_ip: record.ip.clone(),
            busy_service: record.busy_service.clone(),
        };
        match provisioner.provision(&req, config).await? {
            ProvisionOutcome::Provisioned { ip, .. } => {
                let _: Result<(), glide::GlideError> = glide::cmd("RPUSH")
                    .arg(PROVISION_ORDER_KEY)
                    .arg(&ip)
                    .query_async(conn)
                    .await;
                let _ = record_provision(conn).await;
                Ok(serde_json::json!({"status": "provisioned", "ip": ip}))
            }
            other => {
                let _ = record_provision(conn).await;
                Ok(serde_json::json!({"status": "dry_run", "outcome": other}))
            }
        }
    } else if kind == "deprovision" {
        provisioner.deprovision(ip).await?;
        let _: Result<(), glide::GlideError> = glide::cmd("SET")
            .arg(format!("{LAST_DEPROVISION_KEY_PREFIX}{ip}"))
            .arg(chrono::Utc::now().timestamp().to_string())
            .query_async(conn)
            .await;
        let _: Result<usize, glide::GlideError> = glide::cmd("LREM")
            .arg(PROVISION_ORDER_KEY)
            .arg(1)
            .arg(ip)
            .query_async(conn)
            .await;
        let _ = record_provision(conn).await;
        Ok(serde_json::json!({"status": "deprovisioned", "ip": ip}))
    } else {
        anyhow::bail!("unknown pending kind {kind:?} - expected provision|deprovision")
    }
}
