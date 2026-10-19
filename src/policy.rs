// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:Policy integration for captain (Phase ).
//!
//! Thin re-export of the shared bridge (`sentin8::shield::runtime`). Captain
//! is the process supervisor - its control endpoints are platform-operations
//! surfaces gated by the enforced scope-mirror set (step 5).

use std::sync::Arc;

#[allow(unused_imports)]
pub use sentin8::shield::runtime::{
    boot_full, check_policy, evaluate_full, policy_bus_client, request_ctx, require_policy,
    spawn_hot_reload,
};
pub use sentin8::shield::PolicyEngine as Engine;

/// Test helper: build a bare engine for captain (empty until `load` runs in `serve`).
pub fn engine() -> Arc<Engine> {
    sentin8::shield::runtime::engine_for("sentin8:captain")
}
