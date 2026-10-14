// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Bootstrap enrollment credentials — the certificate-bound M2M bootstrap
//! channel (auth design target state).
//!
//! THE PROBLEM: a first-boot workload holds no client certificate, no
//! client_id, and no token. The shared token path cannot bootstrap it
//! (chicken-and-egg), and `/v1/client-cert` is guarded so an
//! anonymous mint is refused. The design answer is "the enroll/bootstrap
//! flow provisions the workload's initial certificate" — this module is
//! that flow, brokered by captain.
//!
//! Captain is the trust anchor for PROCESS identity: it spawns every
//! service (including acme), so it is the one component that can securely
//! distribute a shared secret to exactly the processes it owns.
//!
//! Mechanism:
//! 1. At boot, captain generates a 32-byte random enrollment secret,
//! persists it ENCRYPTED (AES-256-GCM via `sentin8-crypto`, key derived
//! from `SENTIN8_BOOTSTRAP_MASTER_KEY`, falling back to
//! `SENTIN8_AUTH_MASTER_KEY`) under the run dir (`SENTIN8_RUN_DIR`, dev
//! `.run/`), mode 0600 — restart-safe across a captain self-upgrade
//! (the successor re-reads the same file).
//! 2. Captain injects the secret into EVERY child process env as
//! `SENTIN8_BOOTSTRAP_ENROLLMENT` — acme included — so acme can verify
//! the claim LOCALLY (no auth round-trip, no chicken-egg).
//! 3. Acme's `/v1/client-cert` guard admits a request presenting
//! `X-Sentin8-Bootstrap-Enrollment: <secret>` ONLY for minting
//! `CN=m2m-*` client certs (enrollment scope; never TLS server certs),
//! logs the mint at warn level, and honors an expiry window
//! (captain-stamped `SENTIN8_BOOTSTRAP_ENROLLMENT_TS`; 10 min).
//!
//! Trust model: the secret is process-scoped (never leaves the host's
//! spawned processes), time-boxed, encrypted at rest, and useless for
//! anything but enrollment minting. A compromised service holding it can
//!
//! - mint client certs for arbitrary workload NAMES — bounded exactly like
//! the enroll path itself; the DCR scope gate (`service_name` grants)
//! still decides whether a cert with that CN may register. Rotation is
//! per captain boot; the file is removed on graceful shutdown.
//!
//! CA-key isolation is preserved: captain never touches the CA hierarchy;
//! acme remains the only minter.

// The enrollment claim contract (env names, TTL, freshness check) lives in
// `sentin8-config::bootstrap` so captain (producer) and acme (verifier)
// agree on the exact same rules — see the shared module's documentation for
// the trust model. Captain re-exports for its own spawn sites.
pub use sentin8::config::bootstrap::{claim_is_valid, ENV_ENROLLMENT, ENV_ENROLLMENT_TS};

/// The on-disk credential record (JSON) — encrypted at rest.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct EnrollmentRecord {
    /// Hex-encoded 32-byte enrollment secret.
    secret: String,
    /// Generation timestamp (unix seconds) — expiry anchor.
    generated_at: i64,
}

/// Generate (or load) the enrollment credential and return
/// `(secret_hex, generated_at)`. The file lives under `{run_dir}/
/// bootstrap-enrollment.json.enc`, AES-256-GCM sealed with a key derived
/// from the bootstrap master key. An existing valid record is reused so a
/// captain self-upgrade keeps the same credential; a stale record (older
/// than TTL) is regenerated.
pub fn ensure_enrollment() -> anyhow::Result<(String, i64)> {
    let path = enrollment_path();
    if let Some((secret, ts)) = read_record(&path) {
        let ts: i64 = ts.parse().unwrap_or(0);
        if claim_is_valid(&secret, ts) {
            return Ok((secret, ts));
        }
        // TTL expired. RE-STAMP (keep the secret, bump the timestamp,
        // re-seal) rather than generating a new secret: every already-
        // spawned workload holds the spawn-time env copy, and a NEW secret
        // would orphan them — acme verifies the caller's claim against the
        // CURRENT record, so a rotation invalidates every live first-boot
        // caller until it respawns (: mid-boot rotation
        // 401'd every bearer-less DCR caller for the rest of the window).
        // The freshness of a claim is enforced by its own timestamp
        // (`claim_is_valid`), so re-stamping keeps the rotation semantics
        // (old claims expire) while keeping the fleet's outstanding env
        // copies valid.
        tracing::info!("bootstrap enrollment credential expired — re-stamping");
        let now = chrono::Utc::now().timestamp();
        write_record(&path, &secret, now)?;
        return Ok((secret, now));
    }
    let secret = random_secret();
    let now = chrono::Utc::now().timestamp();
    write_record(&path, &secret, now)?;
    tracing::info!(path = %path.display(), ttl_secs = sentin8::config::bootstrap::TTL_SECS, "generated bootstrap enrollment credential");
    Ok((secret, now))
}

/// The enrollment file path: `{run_dir}/bootstrap-enrollment.json.enc`.
fn enrollment_path() -> std::path::PathBuf {
    std::path::Path::new(&sentin8::config::run_dir()).join("bootstrap-enrollment.json.enc")
}

/// The master key for the enrollment envelope: derive from
/// `SENTIN8_BOOTSTRAP_MASTER_KEY` (dedicated) falling back to
/// `SENTIN8_AUTH_MASTER_KEY` (the auth envelope key, always set in dev).
fn master_key() -> anyhow::Result<sentin8::crypto::MasterKey> {
    let material = std::env::var("SENTIN8_BOOTSTRAP_MASTER_KEY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| std::env::var("SENTIN8_AUTH_MASTER_KEY").ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no master key for the bootstrap enrollment credential — set \
                 SENTIN8_BOOTSTRAP_MASTER_KEY (or SENTIN8_AUTH_MASTER_KEY)"
            )
        })?;
    Ok(sentin8::crypto::derive_key(material.as_bytes()))
}

/// Read + decrypt + parse the enrollment record. Returns
/// `(secret_hex, generated_at)`.
fn read_record(path: &std::path::Path) -> Option<(String, String)> {
    let envelope = std::fs::read_to_string(path).ok()?;
    let key = master_key().ok()?;
    let plaintext = sentin8::crypto::open_str(&key, &envelope).ok()?;
    let plaintext = String::from_utf8(plaintext).ok()?;
    let record: EnrollmentRecord = serde_json::from_str(&plaintext).ok()?;
    Some((record.secret, record.generated_at.to_string()))
}

/// Encrypt + write the enrollment record (0600 file; the run dir is
/// host-local). `sentin8-crypto` has no string seal — use `seal` over the
/// JSON bytes.
fn write_record(path: &std::path::Path, secret: &str, generated_at: i64) -> anyhow::Result<()> {
    let record = serde_json::json!({ "secret": secret, "generated_at": generated_at });
    let key = master_key()?;
    let envelope = sentin8::crypto::seal(&key, serde_json::to_string(&record)?.as_bytes())
        .map_err(|e| anyhow::anyhow!("seal bootstrap enrollment: {e}"))?;
    if let Some(parent) = std::path::Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, envelope)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Remove the enrollment credential (graceful shutdown — the next boot
/// generates a fresh one; a leaked file must never outlive the fleet).
pub fn clear_enrollment() {
    let path = enrollment_path();
    if std::fs::remove_file(&path).is_ok() {
        tracing::info!(path = %path.display(), "removed bootstrap enrollment credential");
    }
}

/// TTL rotation — re-stamp the record BEFORE the TTL expires, keeping the
/// same secret (see `ensure_enrollment`'s expiry branch for why the secret
/// is never rotated under a live fleet). Called from the monitor tick
/// (captain DESIGN §7 task topology): `ensure_enrollment` alone runs only
/// at boot/spawn, so after the first TTL window acme rejected every
/// bearer-less first-boot DCR with 401 — the record on disk was stale,
/// `claim_is_valid` failed, and the caller holds no bearer to fall back on
/// (CAPT-ENROLL-1: the sys→auth provisioning Flow failed permanently and
/// org creation 403'd every CLI verify). Idempotent: a fresh record is
/// left untouched; re-stamping is cheap (one seal + write per TTL window).
pub fn restamp_enrollment_if_expiring() {
    let path = enrollment_path();
    let Some((secret, ts_str)) = read_record(&path) else {
        // No record on disk: nothing to keep alive. Boot/spawn generate it.
        return;
    };
    let ts: i64 = ts_str.parse().unwrap_or(0);
    if sentin8::config::bootstrap::claim_is_valid(&secret, ts) {
        // Fresh enough — the renewal margin below is what drives re-stamps;
        // a still-valid record needs no write this tick.
        let now = chrono::Utc::now().timestamp();
        let age = now - ts;
        if age < sentin8::config::bootstrap::TTL_SECS as i64 - RESTAMP_MARGIN_SECS {
            return;
        }
    }
    let now = chrono::Utc::now().timestamp();
    match write_record(&path, &secret, now) {
        Ok(()) => tracing::info!(
            path = %path.display(),
            "bootstrap enrollment credential re-stamped (TTL rotation)"
        ),
        Err(e) => tracing::warn!(error = %e, "bootstrap enrollment TTL re-stamp failed"),
    }
}

/// How long before the TTL expiry the rotation re-stamps (the monitor tick
/// must catch the window even under a slow tick or a missed write).
const RESTAMP_MARGIN_SECS: i64 = 60;

/// 32 random bytes, hex-encoded.
fn random_secret() -> String {
    use rand::RngCore as _;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn random_secret_is_64_hex_chars() {
        let a = random_secret();
        let b = random_secret();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
