// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 Captain - process supervisor & orchestration layer.

#![deny(missing_docs)]

/// Admin UI (RFW) handlers.
pub mod admin_ui;
/// First-boot enrollment record (sealed bootstrap credential).
pub mod bootstrap;
/// Runtime catalog - per-service commands, ports, env, scaling rules.
pub mod catalog;
/// Environment configuration.
pub mod config;
/// HTTP handlers - supervisor control, catalog, health.
pub mod handlers;
/// Health checking of managed processes.
pub mod health;
/// Local (single-machine) process management helpers.
pub mod local;
/// Fleet monitoring - metrics sampling, traffic accounting.
pub mod monitor;
/// Placement decision seams - the one gate every spawn site consults (DESIGN §11.3).
pub mod placement;
/// Shield (Sentin8:Policy) integration - shared bridge re-exports.
pub mod policy;
mod procfs;
/// Machine auto-provisioning (cluster-autoscaler role).
pub mod provision;
/// Service self-registration declarations.
pub mod registration;
/// Load-based scaling (scale-out/in decisions).
pub mod scaler;
/// Axum router and server.
pub mod server;
/// Durable fleet state store (Valkey-backed registry).
pub mod store;
/// Process supervision (spawn, drain, stop).
pub mod supervisor;
