// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Placement decision seams - the ONE gate every spawn site consults
//! (DESIGN.md §11.3).
//!
//! Placement is declarative catalog data (`pin:{ip}` / `anti:{service}` /
//! `singleton`), and enforcement is structural: boot spawn,
//! `POST /v1/captain/start-services`, the scaler's scale-up, and the
//! remote-spawn path (§11.4) all call [`placement_admits`] before spawning.
//! There is no spawn path that bypasses the gate - a violation is refused
//! with a structured reason, never a silent wrong-machine spawn.
//!
//! All seams are pure functions over (entry, local_ip, observed instances)
//! so the full matrix is unit-testable without Valkey; the callers supply
//! the registry snapshot.

use crate::catalog::ServiceCatalogEntry;

/// Why a spawn was refused. `as_str` rides the 409 body and the log line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlacementRefusal {
    /// `pin:{ip}` with a resolved target ≠ this machine.
    /// The refused placement variant.
    PinMismatch {
        /// The machine the pin resolved to.
        pinned_to: String,
    },
    /// `anti:{svc}` and this machine runs an instance of `svc`.
    /// The refused placement variant.
    AntiViolation {
        /// The anti-affinity target that is co-located here.
        anti: String,
    },
    /// `singleton` and an instance of this type is already Active somewhere
    /// in the fleet.
    SingletonViolation,
}

impl PlacementRefusal {
    /// Machine-readable reason for logs + HTTP 409 bodies.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PinMismatch { .. } => "pin_mismatch",
            Self::AntiViolation { .. } => "anti_violation",
            Self::SingletonViolation => "singleton_violation",
        }
    }

    /// Human-readable detail for operators.
    pub fn reason(&self) -> String {
        match self {
            Self::PinMismatch { pinned_to } => {
                format!("service is pinned to machine {pinned_to}")
            }
            Self::AntiViolation { anti } => {
                format!("anti-affinity with '{anti}' which runs on this machine")
            }
            Self::SingletonViolation => "fleet singleton already has a live instance".to_string(),
        }
    }
}

/// The env lookup behind `pin:edge` resolution - an injection seam so
/// unit tests can pin the value WITHOUT mutating process-global env
/// (parallel unit tests would otherwise race on `std::env::set_var`).
/// Production callers pass [`edge_ip_from_env`].
pub type EdgeIpResolver<'a> = &'a dyn Fn() -> Option<String>;

/// The production `pin:edge` resolver - `SENTIN8_CAPTAIN_EDGE_IP` from the
/// operator env (the operator sets it ONLY on the edge host).
pub fn edge_ip_from_env() -> Option<String> {
    std::env::var("SENTIN8_CAPTAIN_EDGE_IP")
        .ok()
        .filter(|s| !s.trim().is_empty())
}

/// Resolve the `pin:edge` pseudo-IP: the edge is wherever the operator
/// says the edge is, exactly like every other placement datum (no
/// hardcoded host). Returns `None` when the pin names a real IP
/// (non-`edge` values pass through verbatim).
pub fn resolve_pin(pin: &str, resolve_edge: EdgeIpResolver<'_>) -> Option<String> {
    if pin == "edge" {
        resolve_edge()
    } else {
        Some(pin.to_string())
    }
}

/// One observed instance row - the registry snapshot callers pass in
/// (already filtered to relevant statuses by the caller).
#[derive(Debug, Clone)]
pub struct ObservedInstance {
    /// The instance's machine IP.
    pub ip: String,
    /// The service type.
    pub service_type: String,
}

/// Does `entry` admit a spawn of its service on THIS machine?
///
/// `local_ip` is this machine; `local_instances` are the instances observed
/// on this machine (any non-terminal status - the anti-affinity check must
/// see `Starting` rows too, or a tier-parallel spawn would co-locate); the
/// caller passes ALL fleet instances so the `singleton` check is global.
///
/// Unconstrained entries admit. Malformed placement keys fail safe to
/// unconstrained (the parse contract - see `parse_placement`).
pub fn placement_admits(
    entry: &ServiceCatalogEntry,
    local_ip: &str,
    local_instances: &[ObservedInstance],
    fleet_instances: &[ObservedInstance],
) -> Result<(), PlacementRefusal> {
    fn edge_env() -> Option<String> {
        edge_ip_from_env()
    }
    placement_admits_inner(
        entry,
        local_ip,
        local_instances,
        fleet_instances,
        &(&edge_env as EdgeIpResolver<'_>),
    )
}

/// The shared decision body behind [`placement_admits`] (and the test
/// seam): `pin:edge` unset resolves by fleet size - with ONE machine (or
/// an empty registry, first boot) that machine self-elects as the edge
/// (DESIGN §11.3 single-machine dev); with a multi-machine fleet the
/// unset refusal stands (the operator must pin the edge - fail-safe,
/// never a wrong-machine :443).
fn placement_admits_inner(
    entry: &ServiceCatalogEntry,
    local_ip: &str,
    local_instances: &[ObservedInstance],
    fleet_instances: &[ObservedInstance],
    resolve_edge: &EdgeIpResolver<'_>,
) -> Result<(), PlacementRefusal> {
    if let Some((crate::catalog::PlacementKind::Pin, pin)) = entry.parse_placement() {
        // "Single-machine fleet" honestly = every observed instance lives
        // on THIS machine (or the registry is empty - first boot). Counting
        // instances would misread one remote instance as a single-machine
        // fleet; counting machines needs distinct IPs.
        if pin == "edge"
            && resolve_edge().is_none()
            && fleet_instances.iter().all(|i| i.ip == local_ip)
        {
            tracing::info!(
                local_ip,
                "pin:edge unset + single-machine fleet - this machine self-elects as the edge"
            );
            // Self-elected: this machine IS the edge - admit without a
            // pin comparison.
        } else if let Some(pinned_to) = resolve_pin(&pin, resolve_edge) {
            if pinned_to != local_ip {
                return Err(PlacementRefusal::PinMismatch { pinned_to });
            }
        } else {
            // `pin:edge` with no operator edge + a multi-machine fleet:
            // nobody is the edge; spawning anywhere would violate the pin
            // the moment an edge is configured. Fail safe: refuse.
            return Err(PlacementRefusal::PinMismatch { pinned_to: pin });
        }
    }
    if let Some((crate::catalog::PlacementKind::AntiAffinity, anti)) = entry.parse_placement() {
        if local_instances.iter().any(|i| i.service_type == anti) {
            return Err(PlacementRefusal::AntiViolation { anti });
        }
    }
    if entry.singleton
        && fleet_instances
            .iter()
            .any(|i| i.service_type == entry.service_type)
    {
        return Err(PlacementRefusal::SingletonViolation);
    }
    Ok(())
}

/// The injection-seam variant of [`placement_admits`] - unit tests pin the
/// `pin:edge` resolution without mutating process-global env (parallel
/// tests would otherwise race on `std::env::set_var`).
#[cfg(test)]
pub(crate) fn placement_admits_with(
    entry: &ServiceCatalogEntry,
    local_ip: &str,
    local_instances: &[ObservedInstance],
    fleet_instances: &[ObservedInstance],
    resolve_edge: EdgeIpResolver<'_>,
) -> Result<(), PlacementRefusal> {
    placement_admits_inner(
        entry,
        local_ip,
        local_instances,
        fleet_instances,
        &resolve_edge,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::ServiceCatalogEntry;

    fn entry(placement: &str, singleton: bool) -> ServiceCatalogEntry {
        ServiceCatalogEntry {
            service_type: "test:svc".into(),
            binary: "test-svc".into(),
            binary_path: String::new(),
            start_priority: 40,
            fixed_port: 0,
            health_port: 0,
            use_http_health: false,
            upgrade_stop_first: false,
            extra_env: Default::default(),
            database_env_vars: Vec::new(),
            placement: placement.into(),
            singleton,
            web_root: String::new(),
        }
    }

    fn inst(ip: &str, service_type: &str) -> ObservedInstance {
        ObservedInstance {
            ip: ip.into(),
            service_type: service_type.into(),
        }
    }

    const ME: &str = "10.0.0.1";

    #[test]
    fn unconstrained_admits() {
        assert!(placement_admits(&entry("", false), ME, &[], &[]).is_ok());
    }

    #[test]
    fn pin_match_admits_and_mismatch_refuses() {
        let e = entry("pin:10.0.0.1", false);
        assert!(placement_admits(&e, ME, &[], &[]).is_ok());
        let e = entry("pin:10.0.0.9", false);
        assert_eq!(
            placement_admits(&e, ME, &[], &[]),
            Err(PlacementRefusal::PinMismatch {
                pinned_to: "10.0.0.9".into()
            })
        );
    }

    #[test]
    fn pin_edge_resolves_via_env() {
        let e = entry("pin:edge", false);
        // Edge resolves to the configured machine (injection seam - no
        // process-global env mutation; parallel tests stay deterministic).
        let edge_at = || Some("10.0.0.7".to_string());
        assert_eq!(
            resolve_pin("edge", &edge_at),
            Some("10.0.0.7".into()),
            "pin:edge resolves through the operator-configured value"
        );
        // With the edge at .7: .7 admits, this machine refuses with the
        // RESOLVED pin (the operator sees WHERE the service belongs, not
        // the pseudo-IP).
        assert!(placement_admits_with(&e, "10.0.0.7", &[], &[], &edge_at).is_ok());
        assert_eq!(
            placement_admits_with(&e, ME, &[], &[], &edge_at),
            Err(PlacementRefusal::PinMismatch {
                pinned_to: "10.0.0.7".into()
            })
        );
    }

    #[test]
    fn pin_edge_unconfigured_single_machine_self_elects() {
        let e = entry("pin:edge", false);
        let unconfigured = || None;
        assert_eq!(resolve_pin("edge", &unconfigured), None);
        // Single machine (empty registry = first boot): self-election admits.
        assert!(placement_admits_with(&e, ME, &[], &[], &unconfigured).is_ok());
        // A SECOND machine elsewhere in the fleet → the unset refusal
        // stands (operator must pin the edge).
        let other = inst("10.0.0.9", "test:other");
        assert!(placement_admits_with(&e, ME, &[], &[other], &unconfigured).is_err());
        // Explicit edge elsewhere (+ single machine? no - fleet has another
        // machine by definition of an edge on it) → mismatch refuses on ME.
        let configured = || Some("10.0.0.5".into());
        assert!(placement_admits_with(&e, ME, &[], &[], &configured).is_err());
    }

    #[test]
    fn anti_refuses_only_when_co_located() {
        let e = entry("anti:test:db", false);
        // The anti target on THIS machine → refuse.
        assert_eq!(
            placement_admits(&e, ME, &[inst(ME, "test:db")], &[]),
            Err(PlacementRefusal::AntiViolation {
                anti: "test:db".into()
            })
        );
        // The anti target on ANOTHER machine → admit (anti-affinity is
        // per-machine co-location, not fleet exclusion).
        assert!(placement_admits(&e, ME, &[], &[inst("10.0.0.2", "test:db")]).is_ok());
        // A Starting sibling counts - tier-parallel spawns must not co-locate.
        assert!(placement_admits(&e, ME, &[inst(ME, "test:db")], &[]).is_err());
    }

    #[test]
    fn singleton_refuses_on_any_fleet_twin() {
        let e = entry("", true);
        assert_eq!(e.service_type, "test:svc");
        // Twin on another machine → refuse everywhere.
        assert_eq!(
            placement_admits(&e, ME, &[], &[inst("10.0.0.2", "test:svc")]),
            Err(PlacementRefusal::SingletonViolation)
        );
        // Twin on this machine → refuse (the local start path too) -
        // the fleet list must see LOCAL twins as well, or a same-machine
        // second spawn would slip past.
        assert_eq!(
            placement_admits(&e, ME, &[inst(ME, "test:svc")], &[inst(ME, "test:svc")]),
            Err(PlacementRefusal::SingletonViolation)
        );
        // No twin → admit.
        assert!(placement_admits(
            &e,
            ME,
            &[inst(ME, "test:db")],
            &[inst("10.0.0.2", "test:db")]
        )
        .is_ok());
    }

    #[test]
    fn malformed_placement_fails_safe_unconstrained() {
        // parse_placement already fails malformed keys to None; the gate
        // must treat them as unconstrained, never as a hard pin.
        assert!(placement_admits(&entry("wat:thing", false), ME, &[], &[]).is_ok());
        assert!(placement_admits(&entry("pin:not-an-ip", false), ME, &[], &[]).is_ok());
    }

    #[test]
    fn refusal_strings_are_stable() {
        assert_eq!(
            PlacementRefusal::PinMismatch {
                pinned_to: "x".into()
            }
            .as_str(),
            "pin_mismatch"
        );
        assert_eq!(
            PlacementRefusal::AntiViolation { anti: "y".into() }.as_str(),
            "anti_violation"
        );
        assert_eq!(
            PlacementRefusal::SingletonViolation.as_str(),
            "singleton_violation"
        );
    }
}
