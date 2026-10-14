// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Captain service self-registration data (REG-15).
//!
//! Output via `--print-registration` flag. The CLI runs the binary with this
//! flag and consumes the JSON to register the service in the platform DB.
//! See.
//!
//! Captain was previously one of the four non-self-describing platform
//! services (bff/proxy/web/captain) whose data came from
//! `vertical-registry.json` via the legacy fallback. PROVISION-12 added the
//! `sentin8:captain` service entry to the registry, and a probe of the
//! captain binary then PANICKED in `CaptainConfig::from_env` (missing
//! `SENTIN8_CAPTAIN_LOCAL_IP`), aborting `dev-destroy.sh` (REG-14 made the
//! probe tolerant). REG-15 closes the gap at the source: captain carries its
//! own registration block like every other service — the flag check runs
//! BEFORE any config loading (self-registration design pattern).
//!
//! The scope-mirror policy set moved here from `vertical-registry.json`
//! (single source of truth — SELFREG: the binary IS the source of truth).

use sentin8::registration::{
    AdminScope, AdminUi, AdminUiPage, PgRole, PolicySetDecl, Registration, RelationDecl,
};

const PG_ROLES: &[PgRole] = &[PgRole {
    scope: "sentin8:captain:admin",
    role: "sentin8_captain_service",
    bypass_rls: false,
    database: "sentin8",
    cross_schema_grants: &[],
}];

const ADMIN_UI_PAGES: &[AdminUiPage] = &[
    AdminUiPage {
        route: "overview",
        label: "Autoscaler",
        ui_endpoint: "/v1/admin/ui/overview",
        data_endpoint: "/v1/admin/autoscaler-status",
        icon: "0xf0d6",
    },
    AdminUiPage {
        route: "machines",
        label: "Fleet Machines",
        ui_endpoint: "/v1/admin/ui/machines",
        data_endpoint: "/v1/admin/autoscaler-machines",
        icon: "0xf522",
    },
];

/// Default declarative policy set (captain design — the enforced
/// scope-mirror that backs the `require_captain_policy` gate). Moved here
/// from `vertical-registry.json` (REG-15) — the binary is the source of
/// truth; the registry JSON keeps no captain policies.
const POLICIES: &[PolicySetDecl] = &[PolicySetDecl {
    policy_set_name: "scope-mirror",
    description: "Action-granular scope permits for sentin8:captain over the LIVE effective scope set. Enforced — step 5 is the only gate.",
    policies: "permit(principal, action == Action::\"sentin8:captain:admin\", resource) when { principal.scopes.contains(\"sentin8:captain:admin\") };\npermit(principal, action == Action::\"sentin8:captain:policy:read\", resource) when { principal.scopes.contains(\"sentin8:captain:policy:read\") };\npermit(principal, action == Action::\"sentin8:captain:policy:write\", resource) when { principal.scopes.contains(\"sentin8:captain:policy:write\") };\npermit(principal, action == Action::\"sentin8:captain:instances:write\", resource) when { principal.scopes.contains(\"sentin8:captain:instances:write\") };",
    schema: None,
    mode: "enforced",
    default_enabled: true,
}];

/// Default ReBAC relation tuples — none declared by this
/// service today.
const RELATIONS: &[RelationDecl] = &[];

/// The OpenAPI spec closure — captain carries no utoipa spec (the management
/// API is operator tooling, not CLI-derivable commands), so the closure
/// emits `null` (the enroll path skips empty openapi output).
fn openapi_spec() -> serde_json::Value {
    serde_json::Value::Null
}

/// Print the registration JSON to stdout.
///
/// With no `--section` argument, outputs the full registration object.
/// With `--section=<name>`, outputs only that section as a standalone JSON value.
/// M2M DCR workload grants (self-registration ): this
/// service's own `certless:<workload>` rows, upserted by `vertical enroll`.
/// The static auth seed is retired — this declaration is the ONLY
/// provisioning path ( "DCR is dynamic").
/// Cover BOTH the full-identity `-policy` spelling (policy_bus_client) and
/// the bare `{short}-policy` spelling (stat_emit); the gate's superset
/// check admits any requested subset.
const M2M_GRANTS: &[sentin8::registration::M2mGrant] = &[
    sentin8::registration::M2mGrant {
        workload: "captain-audit",
        scopes: &["sentin8:sys:audit:write"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:captain",
        scopes: &["sentin8:bus:produce"],
    },
    sentin8::registration::M2mGrant {
        workload: "sentin8:captain-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "captain-policy",
        scopes: &["sentin8:bus:consume", "sentin8:stat:measure"],
    },
    sentin8::registration::M2mGrant {
        workload: "captain-remote",
        // FLEET-4 (DESIGN §11.4): the remote-spawn workload — the
        // cert-bound M2M identity the autoscaler leader presents to
        // another machine's captain when placing a service there.
        // Granular scope: instances only, never the operator admin scope.
        scopes: &["sentin8:captain:instances:write"],
    },
    // TLS-RLS-4 (design/sentin8-vertical-data-plane-contract.md §VDC.7): the database-free HostContextResolver’s resolve workload — cache miss calls Sys `GET /v1/resolve/hostname`.
    sentin8::registration::M2mGrant {
        workload: "sentin8-captain-tls",
        scopes: &["sentin8:sys:instances:read"],
    },
];

/// Handle print.
pub fn print(section: Option<String>) -> anyhow::Result<()> {
    let reg = Registration {
        service_type: "sentin8:captain",
        subdomain: "captain",
        health_path: "/v1/health",
        admin_scopes: &[AdminScope::Tuple(
            "sentin8:captain:admin",
            "sentin8:captain:admin",
        )],
        error_codes: &[],
        consent_providers: &[],
        consent_flows: &[],
        admin_ui: Some(AdminUi {
            label: "Captain",
            icon: "0xf0d6",
            service_flag: "captain",
            pages: ADMIN_UI_PAGES,
        }),
        sql_migrations: vec![],
        pg_roles: PG_ROLES,
        policies: POLICIES,
        relations: RELATIONS,
        event_triggers: &[],
        schedules: &[],
        audit_findings: None,
        service_actions: None,
        m2m_grants: Some(M2M_GRANTS),
        openapi_url: "",
        openapi: openapi_spec,
    };
    sentin8::registration::print_registration(section, &reg, openapi_spec)
}
