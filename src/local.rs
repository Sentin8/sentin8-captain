// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:Captain
// SPDX-License-Identifier: Apache-2.0

//! Local control channel — Unix domain socket listener.
//!
//! Captain additionally serves its management API over
//! `{run_dir}/captain.sock` so local operators can control the platform
//! with kernel-proven credentials instead of a Sentin8:Auth token — the
//! `systemctl` model for `make start/stop/status`. Authorization on this
//! transport is `SO_PEERCRED`: the connecting process's effective uid must
//! be `0` (root) or the socket file's owner (the user that started
//! captain). Everyone else — including other local users — gets 401 on
//! every endpoint, probes included: an untrusted local peer has no
//! business even reading captain's health.
//!
//! The TCP listener keeps the full Shield gate untouched — the LAN
//! RCE surface (`merge-catalog` / `start-services` spawning attacker-chosen
//! binaries) is not affected: the UDS is a local-only, `0600`-permissioned
//! file reachable from no other host.
//!
//! Transport of the authorization decision: the accept loop strips any
//! client-supplied `x-sentin8-local-peer-uid` header, then — only for
//! kernel-authorized peers — injects its own value. The TCP router strips
//! the header unconditionally (anti-spoofing middleware in `server.rs`).
//! `handlers::require_captain_policy` treats a present header as
//! kernel-verified peer identity. This mirrors the platform-wide
//! X-Sentin8-* context-injection pattern (inject at termination, strip
//! client copies).

use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
// Router::call comes from the Service trait — must be in scope.
use tower::Service as _;

/// Header carrying the kernel-proven peer uid on local-socket requests.
/// Injected by the UDS accept loop after stripping client copies; stripped
/// unconditionally on the TCP listener. Presence of this header on a
/// request to `require_captain_policy` means the peer was authorized by
/// `SO_PEERCRED`.
pub const LOCAL_PEER_HEADER: &str = "x-sentin8-local-peer-uid";

/// Is `uid` authorized to control captain on the local socket? Root
/// always is; otherwise the uid must match the socket file's owner (the
/// account that launched captain).
pub fn uid_authorized(uid: u32, socket_owner: Option<u32>) -> bool {
    uid == 0 || (socket_owner == Some(uid))
}

/// Bind the local control socket, returning the listener plus the socket
/// file's owner uid (captured at bind time — the account running captain).
///
/// A stale socket file from a previous captain run is unlinked first; the
/// file gets `0600` permissions so only root (which bypasses file perms)
/// and the owning user can even reach it — defense-in-depth on top of
/// `SO_PEERCRED`.
///
/// Returns `Ok(None)` on non-Unix platforms (no UDS control channel
/// behavior identical to pre- builds).
pub fn bind_local_socket() -> anyhow::Result<Option<(tokio::net::UnixListener, Option<u32>)>> {
    #[cfg(unix)]
    {
        let path = sentin8::config::captain_socket_file();
        if let Some(parent) = std::path::Path::new(&path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Stale socket from a previous run — unlink before rebinding. A
        // live captain is the only process that binds this path (advisory
        // lock exclusivity), so the file cannot belong to a running peer.
        if std::path::Path::new(&path).exists() {
            let _ = std::fs::remove_file(&path);
        }
        let listener = tokio::net::UnixListener::bind(&path)
            .map_err(|e| anyhow::anyhow!("bind local control socket {path}: {e}"))?;
        let owner = socket_owner_uid(&path);
        if let Err(e) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
            tracing::warn!(error = %e, path = %path, "failed to set 0600 on control socket");
        }
        tracing::info!(path = %path, owner = owner.unwrap_or(0), "local control socket listening");
        Ok(Some((listener, owner)))
    }
    #[cfg(not(unix))]
    {
        Ok(None)
    }
}

/// The uid that owns the socket file — the account that started captain.
#[cfg(unix)]
fn socket_owner_uid(path: &str) -> Option<u32> {
    use std::os::unix::fs::MetadataExt as _;
    std::fs::metadata(path).ok().map(|m| m.uid())
}

/// Remove the local control socket on shutdown (run dirs are tmpfs in
/// production; a leftover socket path would make the next bind fail).
pub fn remove_local_socket() {
    #[cfg(unix)]
    {
        let path = sentin8::config::captain_socket_file();
        if let Err(e) = std::fs::remove_file(&path) {
            if e.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(error = %e, path = %path, "failed to remove control socket");
            }
        }
    }
}

/// Strip middleware for the TCP listener: the local-peer header must never
/// arrive over the network — a client-supplied copy is removed before any
/// handler (or the Shield gate) sees it.
pub async fn strip_local_peer_header(
    mut req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    req.headers_mut().remove(LOCAL_PEER_HEADER);
    next.run(req).await
}

/// Serve the shared router on the local control socket.
///
/// Per connection: read `SO_PEERCRED`; unauthorized peers get an immediate
/// 401 (the router is never invoked); authorized peers get the request
/// forwarded with the kernel-proven peer-uid header injected (client
/// copies stripped first).
pub async fn serve_local(
    listener: tokio::net::UnixListener,
    socket_owner: Option<u32>,
    app: axum::Router,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let listener = Arc::new(listener);
    loop {
        let accepted = tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _)) = accepted else {
            continue;
        };
        // Kernel-proven identity of the connecting process (fail-closed:
        // unreadable credentials count as unauthorized).
        let peer_uid = stream.peer_cred().ok().map(|c| c.uid());
        if !peer_uid.is_some_and(|uid| uid_authorized(uid, socket_owner)) {
            let _ = reject_unauthorized(stream).await;
            continue;
        }
        let app = app.clone();
        let uid = peer_uid.unwrap_or(0);
        tokio::spawn(async move {
            let svc = hyper::service::service_fn(move |mut req| {
                let mut app = app.clone();
                async move {
                    // Strip any client-supplied copy, then inject the
                    // kernel-proven value — the only source of truth for
                    // this header on the UDS transport.
                    req.headers_mut().remove(LOCAL_PEER_HEADER);
                    if let Ok(v) = axum::http::HeaderValue::from_str(&uid.to_string()) {
                        req.headers_mut().insert(LOCAL_PEER_HEADER, v);
                    }
                    // Map the hyper request onto axum's Body type so the
                    // shared Router can be called directly.
                    let (parts, body) = req.map(axum::body::Body::new).into_parts();
                    let axum_req = axum::extract::Request::from_parts(parts, body);
                    app.call(axum_req).await
                }
            });
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                .await;
        });
    }
    tracing::info!("local control socket closed");
}

/// Immediate 401 for an unauthorized local peer (kernel did not confirm
/// root or socket-owner). Body text mirrors the TCP gate's 401 wording.
#[cfg(unix)]
async fn reject_unauthorized(
    stream: tokio::net::UnixStream,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let body_bytes: bytes::Bytes = bytes::Bytes::from_static(
        b"{\"error\":\"captain local socket requires root or the socket owner\"}",
    );
    hyper::server::conn::http1::Builder::new()
        .serve_connection(
            hyper_util::rt::TokioIo::new(stream),
            hyper::service::service_fn(move |_req: hyper::Request<hyper::body::Incoming>| {
                let body = http_body_util::Full::new(body_bytes.clone());
                std::future::ready(Ok::<_, std::convert::Infallible>(
                    hyper::Response::builder()
                        .status(hyper::StatusCode::UNAUTHORIZED)
                        .header("content-type", "application/json")
                        .body(body)
                        .unwrap_or_else(|_| {
                            hyper::Response::new(http_body_util::Full::new(
                                bytes::Bytes::from_static(b"unauthorized"),
                            ))
                        }),
                ))
            }),
        )
        .await?;
    Ok(())
}
