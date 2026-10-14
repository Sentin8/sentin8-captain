// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Captain — process supervisor & orchestration layer.
//!
//! Captain owns the Valkey service registry (`captain:svc:*`), spawns and
//! supervises every other Sentin8 backend service on this machine, self-heals
//! crashed processes (up to 3 consecutive restarts, then alerts),
//! auto-scales busy services (up to `max_instances` per service type per
//! machine), and retires idle excess capacity. TLS and Proxy read the
//! registry via pub/sub to build their dynamic backend lists.
//!
//! Captain sends its logs to Log over UDP (like every other service) AND
//! writes them to `.run/logs/captain.log` (the sentin8 CLI redirects
//! captain's stdout to this file). The Log feedback-loop guard is handled
//! in `catalog.rs` — when captain spawns log, it sets
//! `SENTIN8_LOG_DESTINATIONS=""` so log doesn't echo to itself.
//!
//! See.

mod admin_ui;
mod bootstrap;
mod catalog;
mod config;
mod handlers;
mod health;
mod local;
mod monitor;
mod placement;
mod policy;
mod procfs;
mod provision;
mod scaler;
mod server;
mod store;
mod supervisor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Self-registration flag (REG-15) — check BEFORE any config/env loading
    // (self-registration design pattern): `CaptainConfig::from_env`
    // requires SENTIN8_CAPTAIN_LOCAL_IP, which only `captain start` sets; a
    // probe must never pay that gate. The enroll path runs the binary with
    // the flag and consumes the JSON (self-describing service, SELFREG-8/9).
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--print-registration") {
        let section = args
            .iter()
            .find_map(|a| a.strip_prefix("--section="))
            .map(|s| s.to_string());
        return sentin8_captain_server::registration::print(section);
    }

    // Install the Graviola PQ crypto provider before any reqwest HTTPS call
    // the policy admin surface's auth client (token verification against
    // Sentin8:Auth) builds one, and reqwest panics "No provider set" without
    // a provider (COLD-START-1).
    let _ = sentin8::tls::crypto::sentin8_pq_provider().install_default();

    let _ = dotenvy::dotenv();
    let _ = sentin8::middleware::error_metrics::init_tracing_with_metrics(
        "sentin8:captain",
        std::env::var("RUST_LOG").ok().as_deref().unwrap_or("info"),
    );

    // Seed the captain's OWN enrollment env (the boot/spawn paths call
    // `ensure_enrollment` for children, but the captain's internal
    // policy/bus DCR loops run in THIS process and forward the claim from
    // its env — without this seeding they present empty headers and acme
    // 401s them, minting nothing for `sentin8:captain*` workloads).
    if let Ok((secret, ts)) = crate::bootstrap::ensure_enrollment() {
        // SAFETY: main boot, before any task spawns.
        std::env::set_var(crate::bootstrap::ENV_ENROLLMENT, &secret);
        std::env::set_var(crate::bootstrap::ENV_ENROLLMENT_TS, ts.to_string());
    }

    // Valkey certificate identity (group DESIGN.md §3.1): the FIRST Valkey
    // connection (metrics publisher, service discovery, the registry) must
    // already hold the `sentin8:captain` pair — the plane authenticates by
    // certificate and has no plaintext fallback. At a FRESH boot acme is
    // not up yet (captain spawns it), so the mint is NON-FATAL here: a
    // background loop keeps minting-or-loading until the pair lands, and
    // the consumers that fail without it degrade exactly like they do on
    // a Valkey outage (retry / poll-only). On any boot where the pair
    // persists (every boot after the first), this completes immediately.
    {
        let issuer = sentin8::config::Sentin8Config::from_env().sentin8_auth_issuer();
        let ca_path = sentin8::auth::m2m::platform_ca_path();
        match sentin8::auth::m2m::ensure_workload_certificate(&issuer, "sentin8:captain", &ca_path)
            .await
        {
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "captain: Valkey identity not yet mintable (acme not up?) — \
                     background retry until it lands; Valkey consumers degrade meanwhile"
                );
                tokio::spawn(async move {
                    loop {
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        match sentin8::auth::m2m::ensure_workload_certificate(
                            &issuer,
                            "sentin8:captain",
                            &ca_path,
                        )
                        .await
                        {
                            Ok(_) => {
                                tracing::info!(
                                    "captain: Valkey identity minted — Valkey consumers connect on their next retry"
                                );
                                break;
                            }
                            Err(_) => continue,
                        }
                    }
                });
            }
        }
    }

    sentin8::middleware::error_metrics::spawn_publisher(
        // VALKEYDERIVE-1: override → else the plane-derived URL.
        std::env::var("VALKEY_URL")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| sentin8::config::service_valkey_url()),
        "sentin8:captain",
    );

    let config = config::CaptainConfig::from_env();
    tracing::info!(
        service = "sentin8:captain",
        // BUILDID-1: the full identity — {version}+{hash}[.d] — in the
        // banner; the spawn-seeded registry entry keeps version/build raw
        // (the monitor overwrites both from the first health probe).
        version = %sentin8::build_info::id(),
        port = config.port,
        local_ip = %config.local_ip,
        managed_count = config.catalog.len(),
        "service starting"
    );

    let addr = format!("0.0.0.0:{}", config.port);
    let tls = sentin8::tls::Sentin8Tls::builder()
        .service_identity("sentin8:captain")
        .build()
        .await?;
    server::serve(config, addr, tls).await
}
