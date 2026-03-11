//! HTTP server for health checks, metrics, and debug endpoints.
//!
//! Serves on `metrics_bind` address (e.g. "0.0.0.0:9090"):
//! - `/healthz`  — liveness probe (always 200)
//! - `/readyz`   — readiness probe (200 if events flowing, 503 otherwise)
//! - `/metrics`  — Prometheus text exposition format
//! - `/debug/state` — JSON dump of internal state

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use prometheus_client::registry::Registry;

use crate::event_loop::EventStats;
use crate::export::metrics::AgentMetrics;

/// Shared state for the HTTP server.
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<Registry>,
    pub stats: Arc<EventStats>,
    pub metrics: AgentMetrics,
    pub worker_count: usize,
}

/// Start the HTTP server on the given bind address.
///
/// Runs until the process exits. Should be spawned as a background task.
pub async fn start_http_server(bind: String, state: AppState) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics_handler))
        .route("/debug/state", get(debug_state))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!(bind = %bind, "HTTP server started");
    axum::serve(listener, app).await?;
    Ok(())
}

/// Liveness probe — always returns 200 "ok".
async fn healthz() -> &'static str {
    "ok"
}

/// Readiness probe — 200 if we've received any events (RingBuf attached and producing),
/// 503 otherwise.
async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    if state.stats.events_received.load(Ordering::Relaxed) > 0 {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

/// Prometheus metrics endpoint — text exposition format.
async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    // Sync latest stats into prometheus counters before encoding
    state.metrics.sync_from_stats(&state.stats);
    let body = super::metrics::encode_metrics(&state.registry);
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

/// Debug state endpoint — JSON with internal counters and configuration.
async fn debug_state(State(state): State<AppState>) -> Json<serde_json::Value> {
    let received = state.stats.events_received.load(Ordering::Relaxed);
    let dropped = state.stats.events_dropped.load(Ordering::Relaxed);
    let processed = state.stats.events_processed.load(Ordering::Relaxed);
    let active = state.stats.active_connections.load(Ordering::Relaxed);
    let drops_rate = state.stats.drops_rate_limit.load(Ordering::Relaxed);
    let drops_channel = state.stats.drops_channel_full.load(Ordering::Relaxed);
    let drops_parser = state.stats.drops_parser_error.load(Ordering::Relaxed);
    let ringbuf_pending = received.saturating_sub(processed);

    Json(serde_json::json!({
        "events_received": received,
        "events_dropped": dropped,
        "events_processed": processed,
        "active_connections": active,
        "worker_count": state.worker_count,
        "drops": {
            "rate_limit": drops_rate,
            "channel_full": drops_channel,
            "parser_error": drops_parser,
        },
        "ringbuf_approx_pending": ringbuf_pending,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn make_test_state() -> AppState {
        let (metrics, registry) = AgentMetrics::new();
        AppState {
            registry: Arc::new(registry),
            stats: Arc::new(EventStats::new()),
            metrics,
            worker_count: 4,
        }
    }

    fn make_app(state: AppState) -> Router {
        Router::new()
            .route("/healthz", get(healthz))
            .route("/readyz", get(readyz))
            .route("/metrics", get(metrics_handler))
            .route("/debug/state", get(debug_state))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_healthz() {
        let app = make_app(make_test_state());
        let resp = app
            .oneshot(Request::get("/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"ok");
    }

    #[tokio::test]
    async fn test_readyz_not_ready() {
        let state = make_test_state();
        let app = make_app(state);
        let resp = app
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_readyz_ready() {
        let state = make_test_state();
        state.stats.events_received.fetch_add(1, Ordering::Relaxed);
        let app = make_app(state);
        let resp = app
            .oneshot(Request::get("/readyz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_metrics_endpoint() {
        let state = make_test_state();
        state.stats.events_received.fetch_add(42, Ordering::Relaxed);
        state
            .stats
            .events_processed
            .fetch_add(40, Ordering::Relaxed);
        state
            .stats
            .active_connections
            .fetch_add(3, Ordering::Relaxed);
        let app = make_app(state);
        let resp = app
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "text/plain; version=0.0.4; charset=utf-8"
        );
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("panopticon_events_received_total"));
        assert!(
            text.contains("panopticon_events_received_total 42"),
            "metrics text:\n{}",
            text
        );
        assert!(text.contains("panopticon_events_processed_total 40"));
        assert!(text.contains("panopticon_active_connections 3"));
        assert!(text.contains("panopticon_ringbuf_approx_pending 2"));
    }

    #[tokio::test]
    async fn test_metrics_endpoint_syncs_latest_stats_each_scrape() {
        let state = make_test_state();
        let app = make_app(state.clone());

        state.stats.events_received.fetch_add(10, Ordering::Relaxed);
        state.stats.events_processed.fetch_add(6, Ordering::Relaxed);
        let first = app
            .clone()
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let first_body = axum::body::to_bytes(first.into_body(), 8192).await.unwrap();
        let first_text = String::from_utf8(first_body.to_vec()).unwrap();
        assert!(
            first_text.contains("panopticon_events_received_total 10"),
            "first metrics text:\n{}",
            first_text
        );
        assert!(first_text.contains("panopticon_ringbuf_approx_pending 4"));

        state.stats.events_received.fetch_add(7, Ordering::Relaxed);
        state.stats.events_processed.fetch_add(7, Ordering::Relaxed);
        let second = app
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let second_body = axum::body::to_bytes(second.into_body(), 8192)
            .await
            .unwrap();
        let second_text = String::from_utf8(second_body.to_vec()).unwrap();
        assert!(second_text.contains("panopticon_events_received_total 17"));
        assert!(second_text.contains("panopticon_events_processed_total 13"));
        assert!(second_text.contains("panopticon_ringbuf_approx_pending 4"));
    }

    #[tokio::test]
    async fn test_debug_state_json() {
        let state = make_test_state();
        state
            .stats
            .events_received
            .fetch_add(100, Ordering::Relaxed);
        state
            .stats
            .events_processed
            .fetch_add(90, Ordering::Relaxed);
        state.stats.drops_rate_limit.fetch_add(5, Ordering::Relaxed);
        let app = make_app(state);
        let resp = app
            .oneshot(Request::get("/debug/state").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 8192).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["events_received"], 100);
        assert_eq!(json["events_processed"], 90);
        assert_eq!(json["worker_count"], 4);
        assert_eq!(json["drops"]["rate_limit"], 5);
        assert_eq!(json["ringbuf_approx_pending"], 10);
    }
}
