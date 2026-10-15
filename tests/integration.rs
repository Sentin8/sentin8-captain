// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

// Captain unit tests — supervisor + scaler pure seams (testing-strategy
// §3.1; TEST-1/TEST-2 in services/captain/BACKLOG.md).
//
// Pure-testable seams only:
//   - supervisor: `backoff_delay_secs`, the intentionally-stopped pid set
//     (Stopped vs Killed distinction), MAX_RESTARTS policy constant.
//   - store: `ServiceInstance` valkey-key + instance-key derivation,
//     JSON roundtrip of the registry record (Valkey HGETALL payload).
//   - scaler: port-scan decision inputs are Valkey-bound; the threshold
//     constants are pinned so accidental retuning is caught.
//
// Valkey-backed flows (self_heal spawn, stop phases) run under
// `make test-rust-integration` after `make infra-up` (runtime-skip).

use sentin8_captain_server::store::ServiceInstance;
use sentin8_captain_server::supervisor;

// ── Supervisor: restart backoff ─────────────────────────────────────────

#[test]
fn backoff_doubles_per_restart() {
    // 1, 2, 4, 8 — exponential.
    assert_eq!(supervisor::backoff_delay_secs(0), 1);
    assert_eq!(supervisor::backoff_delay_secs(1), 2);
    assert_eq!(supervisor::backoff_delay_secs(2), 4);
    assert_eq!(supervisor::backoff_delay_secs(3), 8);
}

#[test]
fn backoff_never_negative_count() {
    // Defensive: a negative restart_count must not panic (checked_shl path).
    assert_eq!(supervisor::backoff_delay_secs(-1), 1);
}

#[test]
fn backoff_caps_at_16_seconds() {
    // 1u64.checked_shl(n).unwrap_or(16) — the cap pins the max wait.
    assert_eq!(supervisor::backoff_delay_secs(4), 16);
    assert_eq!(supervisor::backoff_delay_secs(100), 16);
}

// ── Supervisor: intentionally-stopped pid set (Stopped vs Killed) ──────

#[test]
fn intentionally_stopped_roundtrip() {
    let pid = 400_001u32;
    supervisor::forget_intentionally_stopped(pid);
    assert!(!supervisor::is_intentionally_stopped(pid));
    supervisor::mark_intentionally_stopped(pid);
    assert!(
        supervisor::is_intentionally_stopped(pid),
        "marked pid is Stopped"
    );
    supervisor::forget_intentionally_stopped(pid);
    assert!(
        !supervisor::is_intentionally_stopped(pid),
        "forgotten pid is Killed"
    );
}

#[test]
fn intentionally_stopped_is_per_pid() {
    let a = 400_002u32;
    let b = 400_003u32;
    supervisor::forget_intentionally_stopped(a);
    supervisor::forget_intentionally_stopped(b);
    supervisor::mark_intentionally_stopped(a);
    assert!(supervisor::is_intentionally_stopped(a));
    assert!(
        !supervisor::is_intentionally_stopped(b),
        "other pids unaffected"
    );
    supervisor::forget_intentionally_stopped(a);
}

#[test]
fn max_restarts_policy() {
    // Give-up threshold: after 3 restarts Captain alerts instead of retrying.
    assert_eq!(supervisor::MAX_RESTARTS, 3);
}

// ── Monitor: TLS warm-up probe classification (CAPT-PROBE-3) ────────────

#[test]
fn probe_signature_warm_rejected_forms() {
    use sentin8_captain_server::monitor::{probe_error_signature, WarmUpSignature};
    // The alert text the sentin8-tls resolver surfaces while a cert fetch
    // is in flight (the incident's signature).
    assert_eq!(
        probe_error_signature("sentin8-tls: alert AccessDenied during TLS handshake"),
        WarmUpSignature::WarmRejected
    );
    // rustls certificate/handshake error text forms.
    assert_eq!(
        probe_error_signature("unknown certificate for www.example.com"),
        WarmUpSignature::WarmRejected
    );
    assert_eq!(
        probe_error_signature("TLS handshake timed out"),
        WarmUpSignature::WarmRejected
    );
}

#[test]
fn probe_signature_never_connected_is_transport_only() {
    use sentin8_captain_server::monitor::{probe_error_signature, WarmUpSignature};
    // Connect refusal / timeout with no HTTP layer reached (the resolver
    // waiting for the very first cert) — a warm-up failure, not a kill
    // signal, while in grace.
    assert_eq!(
        probe_error_signature(
            "request to https://auth.ops.sys.sentin8.local:3101/v1/health failed: Connection refused"
        ),
        WarmUpSignature::NeverConnected
    );
    assert_eq!(
        probe_error_signature("error sending request for url: operation timed out"),
        WarmUpSignature::NeverConnected
    );
}

#[test]
fn probe_signature_non2xx_is_http_layer_not_warmup() {
    use sentin8_captain_server::monitor::{probe_error_signature, WarmUpSignature};
    // An HTTP answer IS reached — a broken-but-listening service counts
    // toward the kill exactly like before (never masked by the grace).
    assert_eq!(
        probe_error_signature("non-2xx status 500"),
        WarmUpSignature::NonTls,
        "non-2xx is an HTTP-layer answer — the warm-up grace must not mask it"
    );
    let warm = sentin8_captain_server::monitor::tls_warm_up(WarmUpSignature::NonTls);
    assert!(!warm, "NonTls never counts as warm-up");
}

#[test]
fn probe_signature_empty_is_not_warmup() {
    use sentin8_captain_server::monitor::{probe_error_signature, WarmUpSignature};
    assert_eq!(probe_error_signature(""), WarmUpSignature::NonTls);
}

#[test]
fn tls_warm_up_forgives_both_shapes_only() {
    use sentin8_captain_server::monitor::{tls_warm_up, WarmUpSignature};
    assert!(tls_warm_up(WarmUpSignature::WarmRejected));
    assert!(tls_warm_up(WarmUpSignature::NeverConnected));
    assert!(!tls_warm_up(WarmUpSignature::NonTls));
}

#[test]
fn cert_grace_config_defaults_pinned() {
    use sentin8_captain_server::config::CaptainConfig;
    // The defaults are load-bearing for the incident class: a saturated
    // cert-mint window well beyond the 3×probe-kill horizon (120s), and
    // a 5-min-paced last-resort respawner. Pinned so accidental retuning
    // shows up as a test failure. 0 on either knob disables it.
    let config = CaptainConfig {
        port: 0,
        valkey_url: String::new(),
        local_ip: String::new(),
        catalog: Default::default(),
        boot_allow: None,
        start_concurrency: 1,
        monitor_tick_s: 3,
        health_probe_failures: 3,
        cooldown_reset_s: 300,
        cert_grace_s: 120,
        last_resort_respawn_s: 300,
        upgrade_drain_s: 10,
        on_call_operator_id: None,
        port_range: (8002, 8101),
        provision_profile: Default::default(),
        provision_backend: String::new(),
        max_machines: 1,
        min_machines: 1,
        provision_window_s: 60,
        provision_cooldown_s: 300,
        provision_idle_window_s: 600,
    };
    assert_eq!(config.cert_grace_s, 120);
    assert_eq!(config.last_resort_respawn_s, 300);
}

// ── Supervisor: bind-failure startup window (CAPT-10b) ──────────────────

#[test]
fn startup_failure_window_bounds_reap_classification() {
    // The reaper only classifies fresh exits inside this window; a
    // longer-lived process's death is never misread as a bind failure
    // (log files are append-only — an old signature must not linger).
    assert!(supervisor::STARTUP_FAIL_WINDOW_S < 60);
}

// ── Store: registry record shape ────────────────────────────────────────

fn sample_instance() -> ServiceInstance {
    ServiceInstance {
        key: "127.0.0.1:3101".into(),
        service_type: "auth".into(),
        local_ip: "127.0.0.1".into(),
        local_port: 3101,
        pid: 4242,
        start_priority: 40,
        cpu_avg_1m: 12.5,
        memory_avg_1m: 30.0,
        rss_mb_avg_1m: 256.0,
        latency_avg_1m_ms: 5.0,
        last_health_check: Some(1_700_000_000),
        status: "Active".into(),
        restarts: 0,
        started_at: Some(1_700_000_000),
        version: "0.1.0".into(),
        build_hash: "abc123".into(),
        errors: 0,
        warnings: 0,
        api_calls: 42,
    }
}

#[test]
fn valkey_key_namespaces_by_service_type() {
    assert_eq!(
        ServiceInstance::valkey_key("auth"),
        "captain:svc:auth",
        "glob captain:svc:* must match — discovery KEYS scan depends on it"
    );
    // Colon identity embeds cleanly in the key (§6.0).
    assert_eq!(
        ServiceInstance::valkey_key("sentin8:payments:worker"),
        "captain:svc:sentin8:payments:worker",
        "colon identities embed verbatim in the Valkey key (§6.0)"
    );
}

#[test]
fn instance_key_is_ip_port() {
    // The hash field is {ip}:{port} — service_type is NOT in the field,
    // so two services on the same ip:port would collide. Pin the shape.
    assert_eq!(
        ServiceInstance::make_key("auth", "10.0.0.5", 3101),
        "10.0.0.5:3101"
    );
    assert_eq!(
        ServiceInstance::make_key("bff", "10.0.0.5", 3101),
        ServiceInstance::make_key("auth", "10.0.0.5", 3101),
        "documented: field is ip:port regardless of service type"
    );
}

#[test]
fn instance_json_roundtrip_preserves_metrics() {
    // The registry value is a JSON blob read back by list_for_ip /
    // discovery. A serde-default regression silently zeroes metrics.
    let inst = sample_instance();
    let json = serde_json::to_string(&inst).unwrap();
    let back: ServiceInstance = serde_json::from_str(&json).unwrap();
    assert_eq!(back.pid, 4242);
    assert_eq!(back.local_port, 3101);
    assert_eq!(back.cpu_avg_1m, 12.5);
    assert_eq!(back.rss_mb_avg_1m, 256.0);
    assert_eq!(back.status, "Active");
    assert_eq!(back.api_calls, 42);
}

#[test]
fn instance_json_new_fields_default() {
    // Older registry entries (pre rss_mb/version/errors) must still parse —
    // #[serde(default)] on the newer fields is load-bearing for upgrades.
    let legacy = r#"{
        "key": "127.0.0.1:3101", "service_type": "auth", "local_ip": "127.0.0.1",
        "local_port": 3101, "pid": 1, "start_priority": 40,
        "cpu_avg_1m": 0.0, "memory_avg_1m": 0.0, "latency_avg_1m_ms": 0.0,
        "last_health_check": null, "status": "Starting", "restarts": 0,
        "started_at": null
    }"#;
    let inst: ServiceInstance = serde_json::from_str(legacy).unwrap();
    assert_eq!(inst.version, "", "new fields default to empty/zero");
    assert_eq!(inst.errors, 0);
    assert_eq!(inst.warnings, 0);
    assert_eq!(inst.api_calls, 0);
    assert_eq!(inst.rss_mb_avg_1m, 0.0);
}

// ── Scaler: threshold constants ─────────────────────────────────────────

#[test]
fn placement_constraint_parsing() {
    use sentin8_captain_server::catalog::{PlacementKind, ServiceCatalogEntry};
    let mk = |placement: &str| ServiceCatalogEntry {
        service_type: "sentin8:test".into(),
        binary: String::new(),
        binary_path: String::new(),
        start_priority: 0,
        fixed_port: 0,
        health_port: 0,
        use_http_health: false,
        upgrade_stop_first: false,
        extra_env: Default::default(),
        placement: placement.into(),
        singleton: false,
        web_root: String::new(),
        database_env_vars: Vec::new(),
    };
    assert_eq!(mk("").parse_placement(), None);
    assert_eq!(
        mk("pin:10.0.0.5").parse_placement(),
        Some((PlacementKind::Pin, "10.0.0.5".into()))
    );
    assert_eq!(
        mk("anti:sentin8:db").parse_placement(),
        Some((PlacementKind::AntiAffinity, "sentin8:db".into()))
    );
    // Malformed → fails safe to unconstrained.
    assert_eq!(mk("pin:not-an-ip").parse_placement(), None);
    assert_eq!(mk("wat:thing").parse_placement(), None);
    // The singleton flag is catalog data (serde-defaulted false).
    assert!(!mk("").singleton);
}

// ── Placement gate (FLEET-1, DESIGN §11.3) ────────────────────────────

#[test]
fn platform_catalog_carries_fleet_placement_values() {
    // The platform's pinned services: acme is a fleet singleton (the CA
    // plane must never fork), proxy is pinned to the edge + singleton
    // (one :443 data plane), captain is a singleton (mirrors the machine
    // lock). These values are load-bearing for multi-host boots.
    // `default_catalog` is config-private; the entries are reachable via
    // the lib's public catalog accessor.
    let config = sentin8_captain_server::config::default_catalog();
    let acme = config.get("sentin8:acme").expect("acme in catalog");
    assert!(acme.singleton, "acme must be a fleet singleton");
    assert_eq!(acme.placement, "");
    let proxy = config.get("sentin8:proxy").expect("proxy in catalog");
    assert_eq!(proxy.placement, "pin:edge");
    assert!(proxy.singleton, "proxy must be a fleet singleton");
    let captain = config.get("sentin8:captain").expect("captain in catalog");
    assert!(captain.singleton);
    // Unconstrained services admit anywhere.
    let auth = config.get("sentin8:auth").expect("auth in catalog");
    assert_eq!(auth.placement, "");
    assert!(!auth.singleton);
}

#[test]
fn placement_gate_singleton_blocks_any_fleet_twin() {
    use sentin8_captain_server::catalog::ServiceCatalogEntry;
    use sentin8_captain_server::placement::{placement_admits, ObservedInstance};
    let entry = ServiceCatalogEntry {
        service_type: "test:singleton".into(),
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
        singleton: true,
        web_root: String::new(),
    };
    // Twin on ANOTHER machine → refuse here.
    let fleet = vec![ObservedInstance {
        ip: "10.0.0.2".into(),
        service_type: "test:singleton".into(),
    }];
    assert!(placement_admits(&entry, "10.0.0.1", &[], &fleet).is_err());
    // No twin → admit.
    assert!(placement_admits(&entry, "10.0.0.1", &[], &[]).is_ok());
}

// ── Remote-spawn selection seam (FLEET-4, DESIGN §11.4) ─────────────

#[test]
fn select_target_machine_prefers_least_loaded_and_excludes_self() {
    use sentin8_captain_server::provision::{select_target_machine, MachineCandidate};
    let c = |ip: &str, cpu: f32, mem: f32| MachineCandidate {
        ip: ip.into(),
        cpu_pct: cpu,
        mem_pct: mem,
    };
    let machines = vec![
        c("10.0.0.1", 40.0, 60.0),
        c("10.0.0.2", 10.0, 20.0),
        c("10.0.0.3", 70.0, 30.0),
    ];
    // Least-loaded wins; the leader is excluded.
    let picked = select_target_machine(&machines, "10.0.0.1").expect("a candidate");
    assert_eq!(picked.ip, "10.0.0.2");
    // All-but-self-excluded → None.
    let only_self = vec![c("10.0.0.1", 1.0, 1.0)];
    assert!(select_target_machine(&only_self, "10.0.0.1").is_none());
    // Empty → None.
    assert!(select_target_machine(&[], "10.0.0.1").is_none());
}

#[test]
fn scaler_thresholds_are_never_scale() {
    use sentin8_captain_server::catalog;
    // Auto-scaling is disabled by design (2026-08 retune). The constants
    // are pinned so accidental retuning shows up as a test failure.
    assert_eq!(catalog::BUSY_CPU_PCT, 100.0);
    assert_eq!(catalog::BUSY_LATENCY_MS, 999999.0);
    assert_eq!(catalog::BUSY_WINDOW_S, 999999999);
    assert_eq!(catalog::IDLE_CPU_PCT, 0.0);
    assert_eq!(catalog::IDLE_LATENCY_MS, 999999.0);
    assert_eq!(catalog::IDLE_WINDOW_S, 999999999);
    assert_eq!(catalog::MIN_INSTANCES, 1);
    assert_eq!(catalog::MAX_INSTANCES, 1);
    assert_eq!(catalog::GRACE_PERIOD_S, 15);
    assert_eq!(catalog::HEALTH_PATH, "/v1/health");
}

#[test]
fn min_never_exceeds_max() {
    use sentin8_captain_server::catalog;
    assert!(catalog::MIN_INSTANCES <= catalog::MAX_INSTANCES);
}

// ── Monitor: cooldown reset decision (TEST-1) ───────────────────────────

#[test]
fn cooldown_resets_after_healthy_window() {
    use sentin8_captain_server::monitor::cooldown_due;
    // Default config: 3s tick, 300s cooldown → 100 healthy ticks.
    assert!(!cooldown_due(99 * 3, 300, 2), "below the window: no reset");
    assert!(cooldown_due(100 * 3, 300, 2), "at the window: reset");
    assert!(cooldown_due(301, 300, 2), "past the window: reset");
}

#[test]
fn cooldown_skips_clean_instances() {
    use sentin8_captain_server::monitor::cooldown_due;
    // restarts == 0 → nothing to reset, even after a long healthy window.
    assert!(!cooldown_due(10_000, 300, 0));
}

#[test]
fn cooldown_never_fires_for_brief_recovery() {
    use sentin8_captain_server::monitor::cooldown_due;
    // A transient blip (1-2 healthy ticks) must not clear the counter.
    assert!(!cooldown_due(2 * 3, 300, 1));
    assert!(!cooldown_due(0, 300, 1));
}

// ── Scaler: decision paths (TEST-2) ─────────────────────────────────────

fn busy_inst(key: &str, port: u16, cpu: f32, lat: f32) -> ServiceInstance {
    ServiceInstance {
        key: key.into(),
        service_type: "sentin8:bff".into(),
        local_ip: "10.0.0.5".into(),
        local_port: port,
        pid: 1000,
        start_priority: 50,
        cpu_avg_1m: cpu,
        memory_avg_1m: 20.0,
        rss_mb_avg_1m: 128.0,
        latency_avg_1m_ms: lat,
        last_health_check: Some(1_700_000_000),
        status: "Active".into(),
        restarts: 0,
        started_at: Some(1_700_000_000),
        version: "0.1.0".into(),
        build_hash: String::new(),
        errors: 0,
        warnings: 0,
        api_calls: 0,
    }
}

#[test]
fn scaler_busy_requires_all_instances_over_threshold() {
    use sentin8_captain_server::scaler::all_busy;
    // With the never-scale pins (cpu 100, lat 999999) nothing can be busy.
    let none = [busy_inst("a", 8002, 99.0, 1.0)];
    assert!(!all_busy(&none), "99% cpu is below the 100% pin");
    let mixed = [
        busy_inst("a", 8002, 100.0, 1.0),
        busy_inst("b", 8003, 50.0, 1.0),
    ];
    assert!(!all_busy(&mixed), "one calm instance blocks the scale-up");
    let empty: Vec<ServiceInstance> = vec![];
    assert!(!all_busy(&empty), "empty group is never busy");
}

#[test]
fn scaler_idle_requires_both_thresholds() {
    use sentin8_captain_server::scaler::is_idle;
    // IDLE_CPU_PCT = 0 → no cpu value is below it; nothing is ever idle
    // while the pins are in place.
    assert!(!is_idle(&busy_inst("a", 8002, 0.0, 0.0)));
}

#[test]
fn scaler_lifo_never_retires_the_base_instance() {
    use sentin8_captain_server::scaler::lifo_target;
    // base = 8002 (lowest port, started first); scaled instances 8003/8004.
    let base = busy_inst("base", 8002, 1.0, 1.0);
    let mut second = busy_inst("second", 8003, 1.0, 1.0);
    second.started_at = Some(2_000_000_000);
    let mut third = busy_inst("third", 8004, 1.0, 1.0);
    third.started_at = Some(3_000_000_000);
    let started = vec![base, second.clone(), third.clone()];

    // LIFO: the newest non-base instance is the target.
    let target = lifo_target(&started).unwrap();
    assert_eq!(
        target.local_port, 8004,
        "newest scaled instance retires first"
    );

    // Only the base instance → nothing to retire.
    let only_base = vec![busy_inst("base", 8002, 1.0, 1.0)];
    assert!(
        lifo_target(&only_base).is_none(),
        "base instance is protected"
    );

    // Dead candidates (pid == 0) are skipped.
    let mut dead = busy_inst("dead", 8004, 1.0, 1.0);
    dead.pid = 0;
    let with_dead = vec![busy_inst("base", 8002, 1.0, 1.0), dead];
    assert!(
        lifo_target(&with_dead).is_none(),
        "no live candidate → no target"
    );
    let _ = second;
}

#[test]
fn scaler_port_scan_never_double_allocates() {
    use sentin8_captain_server::scaler::pick_free_port;
    let mut used = std::collections::HashSet::new();
    used.insert(8002);
    used.insert(8003);
    // First free port after the used ones, inside the range.
    assert_eq!(pick_free_port(&used, (8002, 8010), |_| false), Some(8004));
    // Foreign process holding the port → skipped.
    let blocked = pick_free_port(&used, (8002, 8010), |p| p == 8004);
    assert_eq!(
        blocked,
        Some(8005),
        "ports held by foreign processes are skipped"
    );
    // Range exhausted → None.
    assert_eq!(pick_free_port(&used, (8002, 8003), |_| false), None);
    // Start of range free → picked.
    let mut other = std::collections::HashSet::new();
    other.insert(8010);
    assert_eq!(pick_free_port(&other, (8002, 8010), |_| false), Some(8002));
}

#[test]
fn parallel_upgrades_get_distinct_ports() {
    // UPGRADE-RACE-1 seam: the reservation key derives deterministically
    // from (ip, port) — the pure seam pins the key shape and the NX
    // semantics simulated by a shared "already reserved" set. Two
    // concurrent pickers scanning the same free range must walk past
    // each other's candidates instead of returning the same port.
    use std::collections::HashSet;
    let mut reserved: HashSet<String> = HashSet::new();
    let try_acquire = |ip: &str, port: u16, reserved: &mut HashSet<String>| {
        let key = format!("captain:port:reserve:{}:{}", ip, port);
        if reserved.contains(&key) {
            None
        } else {
            reserved.insert(key);
            Some(port)
        }
    };
    // First upgrade takes 8004; the second concurrent upgrade must NOT
    // get 8004 — it walks to 8005.
    let a = try_acquire("10.0.0.1", 8004, &mut reserved);
    let b = try_acquire("10.0.0.1", 8004, &mut reserved);
    assert_eq!(a, Some(8004));
    assert_eq!(
        b, None,
        "NX semantics: a reserved port is never handed out twice"
    );
    let c = try_acquire("10.0.0.1", 8005, &mut reserved);
    assert_eq!(
        c,
        Some(8005),
        "the next concurrent upgrade walks to the next candidate"
    );
}

// ── Provisioner: machine auto-provisioning decision seams (PROVISION-8) ──
//
// Pure seams mirroring the TEST-2 scaler pattern (testing-strategy §3.1).
// The decision loop itself is Valkey-bound (live flows would need a fleet);
// these pin the pure decision policy.

fn machine(
    ip: &str,
    cpu: f32,
    mem: f32,
    saturated: bool,
) -> sentin8_captain_server::provision::MachineSample {
    sentin8_captain_server::provision::MachineSample {
        ip: ip.into(),
        cpu_pct: cpu,
        mem_pct: mem,
        used_mb: 4096.0,
        ts: 1_700_000_000,
        saturated,
        saturated_service: if saturated {
            "sentin8:bff".into()
        } else {
            String::new()
        },
    }
}

#[test]
fn provision_profile_parse() {
    use sentin8_captain_server::provision::ProvisionProfile;
    // Unset → Auto (the operational default; with the default noop backend
    // that is a dry-run). Unknown values fail safe to Never — a config typo
    // must not silently enable real provisioning.
    assert_eq!(ProvisionProfile::parse(None), ProvisionProfile::Auto);
    assert_eq!(
        ProvisionProfile::parse(Some("auto")),
        ProvisionProfile::Auto
    );
    assert_eq!(
        ProvisionProfile::parse(Some(" AUTO ")),
        ProvisionProfile::Auto
    );
    assert_eq!(
        ProvisionProfile::parse(Some("manual")),
        ProvisionProfile::Manual
    );
    assert_eq!(
        ProvisionProfile::parse(Some("never")),
        ProvisionProfile::Never
    );
    assert_eq!(
        ProvisionProfile::parse(Some("garbage")),
        ProvisionProfile::Never
    );
}

#[test]
fn provision_profile_default_is_auto() {
    // The #[default] derive pins the operational default: auto.
    use sentin8_captain_server::provision::ProvisionProfile;
    assert_eq!(ProvisionProfile::default(), ProvisionProfile::Auto);
}

#[test]
fn provision_saturation_thresholds() {
    use sentin8_captain_server::provision::is_saturated;
    // At cap → saturated (either axis alone).
    assert!(is_saturated(95.0, 10.0), "cpu at cap saturates");
    assert!(is_saturated(10.0, 95.0), "mem at cap saturates");
    assert!(is_saturated(99.0, 99.0));
    // Below both caps → not saturated.
    assert!(!is_saturated(94.9, 94.9));
    assert!(!is_saturated(0.0, 0.0));
}

#[test]
fn provision_idle_thresholds() {
    use sentin8_captain_server::provision::is_idle_host;
    // Below BOTH thresholds → idle.
    assert!(is_idle_host(4.9, 29.9));
    assert!(is_idle_host(0.0, 0.0));
    // Either axis above → not idle.
    assert!(!is_idle_host(5.0, 10.0), "cpu at threshold is not idle");
    assert!(!is_idle_host(1.0, 30.0), "mem at threshold is not idle");
}

#[test]
fn provision_cooldown_gates_repeated_provisions() {
    use sentin8_captain_server::provision::provision_cooldown_elapsed;
    // First provision ever → allowed immediately.
    assert!(provision_cooldown_elapsed(None, 300));
    // Within the cooldown window → blocked (storm guard, mirrors the
    // §4.7 one-instance-per-tick rule).
    assert!(!provision_cooldown_elapsed(Some(0), 300));
    assert!(!provision_cooldown_elapsed(Some(299), 300));
    // Cooldown elapsed → allowed.
    assert!(provision_cooldown_elapsed(Some(300), 300));
    assert!(provision_cooldown_elapsed(Some(10_000), 300));
}

#[test]
fn provision_scale_in_lifo_never_retires_the_base_machine() {
    use sentin8_captain_server::provision::scale_in_target;
    // Provision order oldest-first: A is the base machine.
    let order = vec![
        "10.0.0.1".to_string(),
        "10.0.0.2".to_string(),
        "10.0.0.3".to_string(),
    ];
    let samples = vec![
        machine("10.0.0.1", 3.0, 10.0, false),
        machine("10.0.0.2", 2.0, 8.0, false),
        machine("10.0.0.3", 1.0, 5.0, false),
    ];
    // All idle → retire the MOST-RECENTLY-provisioned (10.0.0.3), LIFO.
    let target = scale_in_target(&samples, &order).unwrap();
    assert_eq!(target.ip, "10.0.0.3");
}

#[test]
fn provision_scale_in_skips_busy_machines() {
    use sentin8_captain_server::provision::scale_in_target;
    let order = vec!["10.0.0.1".to_string(), "10.0.0.2".to_string()];
    let samples = vec![
        machine("10.0.0.1", 50.0, 60.0, false), // busy — not idle
        machine("10.0.0.2", 1.0, 5.0, false),   // idle
    ];
    let target = scale_in_target(&samples, &order).unwrap();
    assert_eq!(
        target.ip, "10.0.0.2",
        "busy machines are never deprovisioned"
    );
}

#[test]
fn provision_scale_in_no_candidates() {
    use sentin8_captain_server::provision::scale_in_target;
    let order = vec!["10.0.0.1".to_string()];
    let busy = vec![machine("10.0.0.1", 80.0, 90.0, false)];
    assert!(
        scale_in_target(&busy, &order).is_none(),
        "no idle machine → no target"
    );
}

#[test]
fn provision_fleet_size_counts_distinct_machines() {
    // The fleet size is simply the count of fresh host samples — the
    // 2-minute TTL means dead machines drop out automatically.
    let samples = [
        machine("10.0.0.1", 1.0, 1.0, false),
        machine("10.0.0.2", 2.0, 2.0, false),
    ];
    assert_eq!(samples.len(), 2);
    assert_eq!(
        Vec::<sentin8_captain_server::provision::MachineSample>::new().len(),
        0
    );
}

#[test]
fn provision_machine_sample_parses_legacy_annotations() {
    use sentin8_captain_server::provision::MachineSample;
    // Pre-PROVISION-1 payloads have no saturated/saturated_service —
    // must parse defensively (serde-default discipline, TEST-4 pattern).
    let legacy = r#"{"cpu_pct": 12.5, "mem_pct": 40.0, "used_mb": 8192.0, "ts": 1692912345}"#;
    let m = MachineSample::from_json("10.0.0.9", legacy).unwrap();
    assert_eq!(m.ip, "10.0.0.9");
    assert!(!m.saturated, "missing saturated defaults to false");
    assert_eq!(m.saturated_service, "", "missing service defaults to empty");
    // Annotated payload round-trips.
    let annotated = r#"{"cpu_pct": 96.0, "mem_pct": 40.0, "used_mb": 8192.0, "ts": 1, "saturated": true, "saturated_service": "sentin8:bff"}"#;
    let m = MachineSample::from_json("10.0.0.9", annotated).unwrap();
    assert!(m.saturated);
    assert_eq!(m.saturated_service, "sentin8:bff");
    // Garbage JSON → None.
    assert!(MachineSample::from_json("10.0.0.9", "not-json").is_none());
}

#[test]
fn provision_constants_are_sane() {
    use sentin8_captain_server::catalog;
    // The saturation thresholds must be reachable (lower than the never-scale
    // §4.7 machine-cap pins) — otherwise the signal can never fire.
    assert!(catalog::PROVISION_CPU_CAP_PCT < catalog::MACHINE_CPU_CAP_PCT);
    assert!(catalog::PROVISION_MEM_CAP_PCT < catalog::MACHINE_MEM_CAP_PCT);
    // Window + cooldown are positive and the idle window is longer than the
    // scale-out window (deprovision must be harder than provision).
    assert!(catalog::PROVISION_WINDOW_S > 0);
    assert!(catalog::PROVISION_COOLDOWN_S > 0);
    assert!(catalog::PROVISION_IDLE_WINDOW_S >= catalog::PROVISION_WINDOW_S);
    assert!(catalog::PROVISION_IDLE_CPU_PCT < catalog::PROVISION_CPU_CAP_PCT);
    assert!(catalog::PROVISION_IDLE_MEM_PCT < catalog::PROVISION_MEM_CAP_PCT);
}

#[test]
fn provision_bootstrap_command_shape() {
    use sentin8_captain_server::config::CaptainConfig;
    use sentin8_captain_server::provision::ProvisionProfile;
    // The bootstrap command is the backend contract (§4.12.6): captain start
    // on the new machine, pointed at the shared Valkey registry.
    let config = CaptainConfig {
        port: 8000,
        valkey_url: "valkey://10.0.0.50:6379/0".into(),
        local_ip: "10.0.0.1".into(),
        catalog: Default::default(),
        boot_allow: None,
        start_concurrency: 8,
        monitor_tick_s: 3,
        health_probe_failures: 3,
        cooldown_reset_s: 300,
        cert_grace_s: 120,
        last_resort_respawn_s: 300,
        upgrade_drain_s: 10,
        on_call_operator_id: None,
        port_range: (8002, 8101),
        provision_profile: ProvisionProfile::Auto,
        provision_backend: "noop".into(),
        max_machines: 3,
        min_machines: 1,
        provision_window_s: 60,
        provision_cooldown_s: 300,
        provision_idle_window_s: 600,
    };
    let cmd = sentin8_captain_server::provision::bootstrap_command("10.0.0.7", &config);
    assert!(cmd.starts_with("sentin8-cli captain start"), "{cmd}");
    assert!(cmd.contains("--local-ip=10.0.0.7"), "{cmd}");
    assert!(cmd.contains("valkey://10.0.0.50:6379/0"), "{cmd}");
}
