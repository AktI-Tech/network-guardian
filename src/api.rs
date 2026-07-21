//! Loopback HTTP API + static dashboard (privacy: bind 127.0.0.1 only by default).
//!
//! No CORS layer: the dashboard is same-origin. `allow_origin(Any)` would let any
//! website read connection/alert data via a browser on this machine.

use crate::models::AgentStatus;
use crate::sensors::environment;
use crate::threat_database::ThreatDatabase;
use axum::extract::State;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Json};
use axum::routing::get;
use axum::Router;
use futures::stream::Stream;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

const DASHBOARD_HTML: &str = include_str!("../web/index.html");
const DASHBOARD_CSS: &str = include_str!("../web/style.css");
const DASHBOARD_JS: &str = include_str!("../web/app.js");

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<ThreatDatabase>,
    pub started: Instant,
    pub bind: String,
    pub sample_interval_secs: u64,
    pub events: broadcast::Sender<String>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(dashboard))
        .route("/style.css", get(style_css))
        .route("/app.js", get(app_js))
        .route("/api/status", get(api_status))
        .route("/api/connections", get(api_connections))
        .route("/api/alerts", get(api_alerts))
        .route("/api/destinations", get(api_destinations))
        .route("/api/stats", get(api_stats))
        .route("/api/environment", get(api_environment))
        .route("/api/events", get(api_events))
        .with_state(state)
}

pub async fn serve(
    state: AppState,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("🌐 Dashboard: http://{}/", addr);
    println!("   API:       http://{}/api/status", addr);
    println!("   Events:    http://{}/api/events (SSE)", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn dashboard() -> Html<&'static str> {
    Html(DASHBOARD_HTML)
}

async fn style_css() -> impl IntoResponse {
    (
        [(axum::http::header::CONTENT_TYPE, "text/css; charset=utf-8")],
        DASHBOARD_CSS,
    )
}

async fn app_js() -> impl IntoResponse {
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "application/javascript; charset=utf-8",
        )],
        DASHBOARD_JS,
    )
}

async fn api_status(State(state): State<AppState>) -> Json<AgentStatus> {
    let connection_count = state.db.count_connections().unwrap_or(0) as usize;
    let alert_count = state
        .db
        .get_statistics()
        .map(|s| s.total as i64)
        .unwrap_or(0);
    let env = environment::probe_cached();

    Json(AgentStatus {
        motto: "Protecting the builders".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        listening: state.bind.clone(),
        sample_interval_secs: state.sample_interval_secs,
        connection_count,
        alert_count,
        uptime_secs: state.started.elapsed().as_secs(),
        wsl_detected: env.wsl_detected,
        docker_detected: env.docker_detected,
    })
}

async fn api_environment() -> impl IntoResponse {
    Json(environment::probe_cached())
}

async fn api_connections(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.get_recent_connections(500) {
        Ok(rows) => Json(serde_json::json!({ "connections": rows })).into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_alerts(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.get_recent_threat_records(100) {
        Ok(rows) => Json(serde_json::json!({ "alerts": rows })).into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_destinations(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.get_destinations(200) {
        Ok(rows) => Json(serde_json::json!({ "destinations": rows })).into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn api_stats(State(state): State<AppState>) -> impl IntoResponse {
    match state.db.get_statistics() {
        Ok(stats) => Json(stats).into_response(),
        Err(e) => (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

/// Server-Sent Events stream: `{ "type": "tick"|"alert", ... }`
async fn api_events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.events.subscribe();
    let stream = BroadcastStream::new(rx).filter_map(|msg| match msg {
        Ok(data) => Some(Ok(Event::default().data(data))),
        Err(_) => None,
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}
