// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

// Sentin8:Captain registry integration tests (BACKLOG TEST-3).
//
// Live tests against the platform Valkey (`VALKEY_URL`, default
// `valkey://localhost:6379/0`). Skipped automatically when Valkey is
// unreachable — run on a host where `make infra-up` has been executed.
//
// Covered flows (runtime-skip pattern per testing-strategy §2.3):
//   - registry lifecycle: upsert → read → delete → publish
//   - status transitions: mark_starting / mark_active / mark_inactive /
//     mark_stopping / mark_stopped / mark_killed (restarts increment)
//   - advisory lock: acquire / release, dead-pid steal
//   - terminal-state cleanup (Stopped/Killed entries removed at startup)
//   - counters: update_metrics, set_api_calls, set_error_warning_counts,
//     reset_daily_counters, update_version_build
//   - next_free_port / count_for_type_on_ip over the live registry
//   - supervisor self_heal give-up path (restarts >= MAX_RESTARTS)

use std::collections::HashSet;

use sentin8_captain_server::catalog::ServiceCatalogEntry;
use sentin8_captain_server::store::{self, ServiceInstance};
use sentin8_captain_server::{monitor, scaler, supervisor};

fn mk_service_type() -> String {
    // Colon identity form (architecture-principles.md §6.0) with a random
    // service segment — exercises Valkey keys that embed colons.
    format!("captain-it:{}", uuid::Uuid::new_v4().simple())
}

/// Unique synthetic IP per test — registry reads are IP-scoped
/// (`list_for_ip`, `cleanup_terminal_states`, `count_for_type_on_ip`),
/// so a distinct IP makes every test fully independent despite
/// cargo's parallel test threads.
fn mk_ip() -> String {
    let u = uuid::Uuid::new_v4();
    let b = u.as_bytes();
    format!("10.{}.{}.{}", b[0] % 255 + 1, b[1], b[2] % 255 + 1)
}

async fn conn() -> Option<glide::GlideClient> {
    let url = std::env::var("VALKEY_URL").unwrap_or_else(|_| "valkeys://localhost:6379/0".into());
    match sentin8::middleware::valkey_client(&url, "captain-test").await {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("skipping live tests — Valkey unreachable: {e}");
            None
        }
    }
}

fn inst(svc: &str, port: u16, status: &str, restarts: i32) -> ServiceInstance {
    ServiceInstance {
        key: ServiceInstance::make_key(svc, "127.0.0.1", port),
        service_type: svc.into(),
        local_ip: "127.0.0.1".into(),
        local_port: port,
        pid: 0, // no real process — pid_alive(0) is false
        start_priority: 50,
        cpu_avg_1m: 0.0,
        memory_avg_1m: 0.0,
        rss_mb_avg_1m: 0.0,
        latency_avg_1m_ms: 0.0,
        // Fresh timestamp: the proxy freshness gate (last_health_check < 30s)
        // is part of `list_active_for_type`, which `count_for_type_on_ip`
        // builds on — instances must look traffic-ready to be counted.
        last_health_check: Some(chrono::Utc::now().timestamp()),
        status: status.into(),
        restarts,
        started_at: Some(chrono::Utc::now().timestamp()),
        version: "0.1.0".into(),
        build_hash: "abc123".into(),
        errors: 0,
        warnings: 0,
        api_calls: 0,
    }
}

/// Re-key an instance onto a test-specific IP.
fn on_ip(mut i: ServiceInstance, ip: &str) -> ServiceInstance {
    i.local_ip = ip.into();
    i.key = ServiceInstance::make_key(&i.service_type, ip, i.local_port);
    i
}

fn dummy_entry(svc: &str) -> ServiceCatalogEntry {
    ServiceCatalogEntry {
        service_type: svc.into(),
        binary: "true".into(), // exits immediately — never actually spawned in these tests
        binary_path: String::new(),
        start_priority: 50,
        fixed_port: 0,
        health_port: 0,
        use_http_health: true,
        upgrade_stop_first: false,
        extra_env: Default::default(),
        web_root: String::new(),
        database_env_vars: Vec::new(),
        placement: String::new(),
        singleton: false,
    }
}

async fn delete_by_key(conn: &glide::GlideClient, svc: &str, key: &str) {
    use glide::AsyncCommands as _;
    let _: Result<i64, _> = conn
        .hdel::<_, _, i64>(format!("captain:svc:{svc}"), key)
        .await;
}

// ── Registry lifecycle ──────────────────────────────────────────────────

#[tokio::test]
async fn upsert_read_delete_lifecycle() {
    let Some(c) = conn().await else { return };
    let conn = c;
    let svc = mk_service_type();
    let ip = mk_ip();
    let base = on_ip(inst(&svc, 9501, "Starting", 0), &ip);

    store::upsert_instance(&conn, &base).await.unwrap();
    let listed = store::list_for_ip(&conn, &ip).await.unwrap();
    let found = listed.iter().find(|i| i.service_type == svc).unwrap();
    assert_eq!(found.local_port, 9501);
    assert_eq!(found.status, "Starting");

    delete_by_key(&conn, &svc, &base.key).await;
    let listed = store::list_for_ip(&conn, &ip).await.unwrap();
    assert!(
        !listed.iter().any(|i| i.service_type == svc),
        "deleted entry must not reappear"
    );
}

#[tokio::test]
async fn status_transitions_update_the_registry() {
    let Some(c) = conn().await else { return };
    let conn = c;
    let svc = mk_service_type();
    let ip = mk_ip();
    let base = on_ip(inst(&svc, 9502, "Starting", 0), &ip);
    store::upsert_instance(&conn, &base).await.unwrap();

    // Starting → Active (one-tick promotion path).
    store::mark_active(&conn, &base).await.unwrap();
    let listed = store::list_for_ip(&conn, &ip).await.unwrap();
    let after = listed.iter().find(|i| i.service_type == svc).unwrap();
    assert_eq!(after.status, "Active");
    assert!(
        after.last_health_check.is_some(),
        "status transitions refresh last_health_check (proxy freshness gate)"
    );

    // Active → Inactive (drain) → Stopping.
    store::mark_inactive(&conn, after).await.unwrap();
    store::mark_stopping(&conn, after).await.unwrap();
    let listed = store::list_for_ip(&conn, &ip).await.unwrap();
    let stopping = listed.iter().find(|i| i.service_type == svc).unwrap();
    assert_eq!(stopping.status, "Stopping");

    // Stopped (clean exit) — pid cleared, not deleted by mark_stopped.
    store::mark_stopped(&conn, stopping).await.unwrap();
    let listed = store::list_for_ip(&conn, &ip).await.unwrap();
    let stopped = listed.iter().find(|i| i.service_type == svc).unwrap();
    assert_eq!(stopped.status, "Stopped");
    assert_eq!(stopped.pid, 0);

    delete_by_key(&conn, &svc, &base.key).await;
}

#[tokio::test]
async fn killed_increments_restarts() {
    let Some(c) = conn().await else { return };
    let conn = c;
    let svc = mk_service_type();
    let ip = mk_ip();
    let base = on_ip(inst(&svc, 9503, "Active", 0), &ip);
    store::upsert_instance(&conn, &base).await.unwrap();

    let r1 = store::mark_killed(&conn, &base).await.unwrap();
    assert_eq!(r1.restarts, 1, "first kill → restarts = 1");
    assert_eq!(r1.status, "Killed");
    assert_eq!(r1.pid, 0);
    let listed = store::list_for_ip(&conn, &ip).await.unwrap();
    let killed = listed.iter().find(|i| i.service_type == svc).unwrap();
    assert_eq!(killed.status, "Killed");
    assert_eq!(killed.restarts, 1);
    assert_eq!(killed.pid, 0, "mark_killed clears the pid");

    let r2 = store::mark_killed(&conn, killed).await.unwrap();
    assert_eq!(r2.restarts, 2, "second kill → restarts = 2");
    // Invariant 10: the returned snapshot is the FRESH post-increment value —
    // self_heal respawns from it, so a stale pre-increment snapshot can never
    // re-seed the counter (the 2026-10-01 crash-loop: counter pinned, MAX
    // unreachable, ~21k spawns).

    store::reset_restarts(&conn, killed).await.unwrap();
    let listed = store::list_for_ip(&conn, &ip).await.unwrap();
    let reset = listed.iter().find(|i| i.service_type == svc).unwrap();
    assert_eq!(reset.restarts, 0);

    delete_by_key(&conn, &svc, &base.key).await;
}

// ── Advisory lock ───────────────────────────────────────────────────────

#[tokio::test]
async fn advisory_lock_acquire_release_and_steal() {
    let Some(c) = conn().await else { return };
    let conn = c;
    // Use a synthetic IP key so we never fight a real captain's lock.
    let ip = "192.0.2.77"; // TEST-NET-1 — never routable
    let lock_key = format!("captain:lock:{ip}");

    let acquired = store::try_advisory_lock(&conn, ip).await.unwrap();
    assert!(acquired, "lock on an unroutable IP must be free");

    let again = store::try_advisory_lock(&conn, ip).await.unwrap();
    assert!(!again, "second acquisition on the same IP must fail");

    // Plant a dead pid in the lock and verify the steal path.
    {
        use glide::AsyncCommands as _;
        let _: Result<(), _> = conn.set::<_, _, ()>(&lock_key, "999999999").await;
    }
    let stolen = store::try_advisory_lock(&conn, ip).await.unwrap();
    assert!(stolen, "a lock held by a dead pid is stolen");

    store::release_advisory_lock(&conn, ip).await.unwrap();
    let freed = store::try_advisory_lock(&conn, ip).await.unwrap();
    assert!(freed, "after release the lock is acquirable again");
    store::release_advisory_lock(&conn, ip).await.unwrap();
    {
        use glide::AsyncCommands as _;
        let _: Result<(), _> = conn.del::<_, ()>(&lock_key).await;
    }
}

// ── Terminal-state cleanup ──────────────────────────────────────────────

#[tokio::test]
async fn cleanup_terminal_states_removes_stopped_and_killed() {
    let Some(c) = conn().await else { return };
    let conn = c;
    let svc = mk_service_type();
    let ip = mk_ip();
    let stopped = on_ip(inst(&svc, 9504, "Stopped", 0), &ip);
    let killed = on_ip(inst(&svc, 9505, "Killed", 3), &ip);
    let active = on_ip(inst(&svc, 9506, "Active", 0), &ip);
    for i in [&stopped, &killed, &active] {
        store::upsert_instance(&conn, i).await.unwrap();
    }

    let removed = store::cleanup_terminal_states(&conn, &ip).await.unwrap();
    assert_eq!(
        removed, 2,
        "exactly the Stopped + Killed entries are removed"
    );

    let listed = store::list_for_ip(&conn, &ip).await.unwrap();
    assert!(!listed
        .iter()
        .any(|i| i.service_type == svc && i.status == "Stopped"));
    assert!(!listed
        .iter()
        .any(|i| i.service_type == svc && i.status == "Killed"));
    assert!(
        listed
            .iter()
            .any(|i| i.service_type == svc && i.status == "Active"),
        "Active entries survive cleanup"
    );
    delete_by_key(&conn, &svc, &active.key).await;
}

// ── Counters ────────────────────────────────────────────────────────────

#[tokio::test]
async fn metrics_and_counters_roundtrip() {
    let Some(c) = conn().await else { return };
    let conn = c;
    let svc = mk_service_type();
    let ip = mk_ip();
    let base = on_ip(inst(&svc, 9507, "Active", 1), &ip);
    store::upsert_instance(&conn, &base).await.unwrap();

    store::update_metrics(&conn, &base, 12.5, 30.0, 256.0, 3.5)
        .await
        .unwrap();
    store::update_version_build(&conn, &base, Some("9.9.9"), Some("260905-1200"))
        .await
        .unwrap();
    store::set_api_calls(&conn, &ip, &svc, 777).await.unwrap();
    store::set_error_warning_counts(&conn, &ip, &svc, 3, 5)
        .await
        .unwrap();

    let listed = store::list_for_ip(&conn, &ip).await.unwrap();
    let m = listed.iter().find(|i| i.service_type == svc).unwrap();
    assert_eq!(m.cpu_avg_1m, 12.5);
    assert_eq!(m.rss_mb_avg_1m, 256.0);
    assert_eq!(m.latency_avg_1m_ms, 3.5);
    assert_eq!(m.version, "9.9.9");
    assert_eq!(m.api_calls, 777);
    assert_eq!(m.errors, 3);
    assert_eq!(m.warnings, 5);

    let reset = store::reset_daily_counters(&conn, &ip).await.unwrap();
    assert!(reset >= 1);
    let listed = store::list_for_ip(&conn, &ip).await.unwrap();
    let after = listed.iter().find(|i| i.service_type == svc).unwrap();
    assert_eq!(after.restarts, 0);
    assert_eq!(after.errors, 0);
    assert_eq!(after.warnings, 0);
    // api_calls is NOT reset by the daily counter reset (24h rollup overwrites it).
    assert_eq!(after.api_calls, 777);

    delete_by_key(&conn, &svc, &base.key).await;
}

// ── Port pool ───────────────────────────────────────────────────────────

#[tokio::test]
async fn next_free_port_skips_used_live_ports() {
    let Some(c) = conn().await else { return };
    let conn = c;
    let svc = mk_service_type();
    let ip = mk_ip();
    // A live instance occupying a port inside the scan range.
    let holder = on_ip(inst(&svc, 9508, "Active", 0), &ip);
    store::upsert_instance(&conn, &holder).await.unwrap();

    let port = scaler::next_free_port(&conn, &ip, (9508, 9520))
        .await
        .unwrap();
    assert_ne!(
        port, 9508,
        "the port held by a live instance must never be re-allocated"
    );
    // Terminal-state holders do NOT block the port.
    let dead = on_ip(inst(&svc, 9509, "Stopped", 0), &ip);
    store::upsert_instance(&conn, &dead).await.unwrap();
    let port2 = scaler::next_free_port(&conn, &ip, (9509, 9520))
        .await
        .unwrap();
    assert_eq!(port2, 9509, "a Stopped holder's port is reusable");

    delete_by_key(&conn, &svc, &holder.key).await;
    delete_by_key(&conn, &svc, &dead.key).await;
}

#[tokio::test]
async fn count_for_type_on_ip_counts_this_ip_only() {
    let Some(c) = conn().await else { return };
    let conn = c;
    let svc = mk_service_type();
    let ip = mk_ip();
    let mine = on_ip(inst(&svc, 9510, "Active", 0), &ip);
    store::upsert_instance(&conn, &mine).await.unwrap();

    let n = store::count_for_type_on_ip(&conn, &svc, &ip).await.unwrap();
    assert_eq!(n, 1, "exactly one Active instance on this IP");
    // A different IP sees zero.
    let n2 = store::count_for_type_on_ip(&conn, &svc, "203.0.113.9")
        .await
        .unwrap();
    assert_eq!(n2, 0, "instances are IP-scoped");

    delete_by_key(&conn, &svc, &mine.key).await;
}

// ── Self-heal give-up path (restarts >= MAX_RESTARTS) ──────────────────

#[tokio::test]
async fn self_heal_gives_up_after_max_restarts() {
    let Some(c) = conn().await else { return };
    let conn = c;
    let svc = mk_service_type();
    let ip = mk_ip();
    // pid 0 + restarts at the cap → Alerted, entry deleted, no spawn.
    let doomed = on_ip(inst(&svc, 9511, "Killed", supervisor::MAX_RESTARTS), &ip);
    store::upsert_instance(&conn, &doomed).await.unwrap();

    let entry = dummy_entry(&svc);
    let action = supervisor::self_heal(&conn, &doomed, &entry).await.unwrap();
    assert!(
        matches!(action, supervisor::HealAction::Alerted { restarts: 3 }),
        "at MAX_RESTARTS the supervisor alerts instead of respawning"
    );
    let listed = store::list_for_ip(&conn, &ip).await.unwrap();
    assert!(
        !listed.iter().any(|i| i.service_type == svc),
        "the dead instance is removed so its port is freed"
    );
}

#[tokio::test]
async fn self_heal_skips_intentionally_stopped() {
    let Some(c) = conn().await else { return };
    let conn = c;
    let svc = mk_service_type();
    let ip = mk_ip();
    let pid = 4_500_001u32; // not a real process
    let mut stopped = on_ip(inst(&svc, 9512, "Active", 0), &ip);
    stopped.pid = pid;
    store::upsert_instance(&conn, &stopped).await.unwrap();

    supervisor::mark_intentionally_stopped(pid);
    let entry = dummy_entry(&svc);
    let action = supervisor::self_heal(&conn, &stopped, &entry)
        .await
        .unwrap();
    assert!(
        matches!(action, supervisor::HealAction::NoAction),
        "an intentionally-stopped pid is left to its stop() flow"
    );
    supervisor::forget_intentionally_stopped(pid);
    delete_by_key(&conn, &svc, &stopped.key).await;
}

// ── Scaler decision over real registry state ────────────────────────────

#[tokio::test]
async fn scaler_cooldown_decision_runs_over_active_only() {
    let Some(c) = conn().await else { return };
    let conn = c;
    let svc = mk_service_type();
    let ip = mk_ip();
    // Starting instances are invisible to the scaler (one-tick promotion
    // means Started is never produced — CAPTAIN-2 regression guard).
    let starting = on_ip(inst(&svc, 9513, "Starting", 0), &ip);
    store::upsert_instance(&conn, &starting).await.unwrap();

    let n = store::count_for_type_on_ip(&conn, &svc, &ip).await.unwrap();
    assert_eq!(n, 0, "only Active instances count toward scaler decisions");
    delete_by_key(&conn, &svc, &starting.key).await;
}

// ── Daily reset ignores untouched instances ────────────────────────────

#[tokio::test]
async fn reset_daily_counters_is_zero_write_safe() {
    let Some(c) = conn().await else { return };
    let conn = c;
    let svc = mk_service_type();
    let ip = mk_ip();
    let clean = on_ip(inst(&svc, 9514, "Active", 0), &ip);
    store::upsert_instance(&conn, &clean).await.unwrap();
    let _ = store::reset_daily_counters(&conn, &ip).await.unwrap();
    let listed = store::list_for_ip(&conn, &ip).await.unwrap();
    let after = listed.iter().find(|i| i.service_type == svc).unwrap();
    assert_eq!(
        after.restarts, 0,
        "a clean instance stays clean after reset"
    );
    delete_by_key(&conn, &svc, &clean.key).await;
}

// ── Upgrade guard key semantics ─────────────────────────────────────────

#[tokio::test]
async fn upgrade_in_progress_key_is_valkey_backed() {
    let Some(c) = conn().await else { return };
    let conn = c;
    let key = "9515:upgrade-it";
    let upgrade_key = format!("captain:upgrade:{key}");
    {
        use glide::AsyncCommands as _;
        let _: Result<(), _> = conn.del::<_, ()>(&upgrade_key).await;
    }
    assert!(!monitor::is_upgrade_in_progress(&conn, key).await);

    {
        use glide::AsyncCommands as _;
        let _: Result<(), _> = conn
            .set::<_, _, ()>(&upgrade_key, r#"{"phase":"starting"}"#)
            .await;
    }
    assert!(monitor::is_upgrade_in_progress(&conn, key).await);
    {
        use glide::AsyncCommands as _;
        let _: Result<(), _> = conn.del::<_, ()>(&upgrade_key).await;
    }
    assert!(!monitor::is_upgrade_in_progress(&conn, key).await);
}

// The set of service types touched by the tests above is unique per run
// (uuid suffix), so cross-run pollution is impossible; per-test cleanup
// removes the per-type hash keys, and any leftover keys expire with the
// dev Valkey. No shared-state assertions depend on other tests.
#[allow(dead_code)]
fn _unused(_: &HashSet<u16>) {}

// ── Upgrade guard key semantics (CAPT-10: old + new instance keys) ──────

#[tokio::test]
async fn upgrade_guard_matches_both_old_and_new_keys() {
    let Some(c) = conn().await else { return };
    let conn = c;
    let key = "9516:upgrade-dual";
    let new_key = format!("captain:upgrade:new:{key}");
    let old_key = format!("captain:upgrade:{key}");
    {
        use glide::AsyncCommands as _;
        let _: Result<i64, _> = conn.del::<_, i64>(&[&old_key, &new_key]).await;
    }
    // Neither key → no upgrade.
    assert!(!monitor::is_upgrade_in_progress(&conn, key).await);

    // The NEW-instance key alone shields the new row while the run waits
    // for it to go Active (the flapping-instance incident class).
    {
        use glide::AsyncCommands as _;
        let _: Result<i64, _> = conn
            .set::<_, _, i64>(&new_key, r#"{"phase":"spawned"}"#)
            .await;
    }
    assert!(
        monitor::is_upgrade_in_progress(&conn, key).await,
        "the new-instance key must guard the new row during the Active wait"
    );
    {
        use glide::AsyncCommands as _;
        let _: Result<i64, _> = conn.del::<_, i64>(&new_key).await;
    }

    // The OLD-instance key alone still guards as before.
    {
        use glide::AsyncCommands as _;
        let _: Result<i64, _> = conn
            .set::<_, _, i64>(&old_key, r#"{"phase":"draining"}"#)
            .await;
    }
    assert!(monitor::is_upgrade_in_progress(&conn, key).await);

    // Both cleared → guard false.
    {
        use glide::AsyncCommands as _;
        let _: Result<i64, _> = conn.del::<_, i64>(&old_key).await;
    }
    assert!(!monitor::is_upgrade_in_progress(&conn, key).await);
}
