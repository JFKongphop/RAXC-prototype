/*!
RAXC API server — HTTP interface to the smart contract vulnerability scanner.

Usage:
  cargo run --bin api

Endpoints:
  POST /analyze          { "contract": "...solidity code...", "name": "optional" }
                         → { "download_url": "/reports/RAXC_...md", "vulnerability_found": "...", ... }
  GET  /reports/{file}   download the generated markdown report
  GET  /health           liveness check
*/

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use raxc::{analyze, build_markdown, build_qdrant, load_env, match_functions, parse_report_fields};
use tower_http::cors::{Any, CorsLayer};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

// ─── Shared state ─────────────────────────────────────────────────────────────

struct AppState {
    http: Client,
    qdrant: qdrant_client::Qdrant,
    api_key: String,
    /// In-memory report store: filename → markdown content (no disk writes)
    reports: Mutex<HashMap<String, String>>,
}

// ─── Request / response types ─────────────────────────────────────────────────

#[derive(Deserialize)]
struct AnalyzeRequest {
    contract: String,
    #[serde(default = "default_name")]
    name: String,
}

fn default_name() -> String {
    "contract".to_string()
}

#[derive(Serialize)]
struct AnalyzeResponse {
    download_url: String,
    vulnerability_found: String,
    risk_level: String,
    vulnerability_type: String,
    confidence: String,
}

// ─── Error type ───────────────────────────────────────────────────────────────

struct AppError(anyhow::Error);

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(e: E) -> Self {
        AppError(e.into())
    }
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

async fn handle_analyze(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AnalyzeRequest>,
) -> Result<Json<AnalyzeResponse>, AppError> {
    let (report, results) =
        analyze(&state.http, &state.qdrant, &state.api_key, &req.contract).await?;

    let func_matches =
        match_functions(&state.http, &state.qdrant, &state.api_key, &req.contract, 3).await?;

    let (filename, content) = build_markdown(&report, &results, &req.name, Some(&func_matches));

    // Store in memory — no disk write
    state.reports.lock().unwrap().insert(filename.clone(), content);

    let fields = parse_report_fields(&report);

    Ok(Json(AnalyzeResponse {
        download_url: format!("/reports/{}", filename),
        vulnerability_found: fields.vuln_found,
        risk_level: fields.risk_level,
        vulnerability_type: fields.vuln_type,
        confidence: fields.confidence,
    }))
}

async fn download_report(
    State(state): State<Arc<AppState>>,
    Path(filename): Path<String>,
) -> Result<Response, AppError> {
    // Strip directory components to prevent path traversal.
    let safe = std::path::Path::new(&filename)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| anyhow::anyhow!("Invalid filename"))?
        .to_owned();

    let content = state
        .reports
        .lock()
        .unwrap()
        .get(&safe)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("Report not found: {}", safe))?;

    let disposition = format!("attachment; filename=\"{}\"", safe);
    Ok(Response::builder()
        .header(header::CONTENT_TYPE, "text/markdown; charset=utf-8")
        .header(header::CONTENT_DISPOSITION, disposition)
        .body(Body::from(content))
        .unwrap())
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}

// ─── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    load_env();

    let api_key = std::env::var("OPENAI_API_KEY").context("OPENAI_API_KEY not set")?;
    let http = Client::new();
    let qdrant = build_qdrant()?;

    let state = Arc::new(AppState {
        http,
        qdrant,
        api_key,
        reports: Mutex::new(HashMap::new()),
    });

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/analyze", post(handle_analyze))
        .route("/reports/*filename", get(download_report))
        .route("/health", get(health))
        .layer(cors)
        .with_state(state);

    let addr = "0.0.0.0:8080";
    println!("[*] RAXC API server → http://{}", addr);
    println!("[*]   POST /analyze          body: {{\"contract\":\"...\",\"name\":\"optional\"}}");
    println!("[*]   GET  /reports/{{file}}   download the markdown report");
    println!("[*]   GET  /health           liveness check");

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
