use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::Context;
use axum::{Router, extract::State, http::StatusCode, response::IntoResponse, routing::get};
use tokio_util::sync::CancellationToken;

/// Tracks when the last round of checks finished.
///
/// The CronJob this replaces was supervised for free: a hung run was killed by
/// `activeDeadlineSeconds` and the next tick started a fresh process. A
/// long-lived process gives that up, so it exposes its own liveness instead --
/// otherwise a wedged loop would look healthy right up until every monitor in
/// uptime-kuma alarmed at once.
pub struct Health {
    last_round: Mutex<Instant>,
    stale_after: Duration,
}

impl Health {
    pub fn new(stale_after: Duration) -> Self {
        Self {
            last_round: Mutex::new(Instant::now()),
            stale_after,
        }
    }

    pub fn round_completed(&self) {
        *self.last_round.lock().expect("health mutex poisoned") = Instant::now();
    }

    fn age(&self) -> Duration {
        self.last_round
            .lock()
            .expect("health mutex poisoned")
            .elapsed()
    }
}

async fn healthz(State(health): State<Arc<Health>>) -> impl IntoResponse {
    let age = health.age();

    if age > health.stale_after {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("stale: last round finished {age:?} ago\n"),
        )
    } else {
        (StatusCode::OK, format!("ok: last round finished {age:?} ago\n"))
    }
}

pub async fn serve(port: u16, health: Arc<Health>, token: CancellationToken) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .with_state(health);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("could not bind health server on {addr}"))?;

    axum::serve(listener, app)
        .with_graceful_shutdown(async move { token.cancelled().await })
        .await
        .context("health server failed")
}
