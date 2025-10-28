//! x402 Facilitator HTTP entrypoint.
//!
//! This binary launches an Axum-based HTTP server that exposes the x402 protocol interface
//! for payment verification and settlement via Ethereum-compatible networks.
//!
//! Endpoints:
//! - `GET /verify` – Supported verification schema
//! - `POST /verify` – Verify a payment payload against requirements
//! - `GET /settle` – Supported settlement schema
//! - `POST /settle` – Settle an accepted payment payload on-chain
//! - `GET /supported` – List supported payment kinds (version/scheme/network)
//!
//! This server includes:
//! - OpenTelemetry tracing via `TraceLayer`
//! - CORS support for cross-origin clients
//! - Ethereum provider cache for per-network RPC routing
//!
//! Environment:
//! - `.env` values loaded at startup
//! - `HOST`, `PORT` control binding address
//! - `OTEL_*` variables enable tracing to systems like Honeycomb

use axum::Router;
use axum::http::Method;
use axum::{Json, response::IntoResponse};
use dotenvy::dotenv;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use std::str::FromStr;
use alloy::hex;

use crate::facilitator_local::FacilitatorLocal;
use crate::provider_cache::ProviderCache;
use crate::sig_down::SigDown;
use crate::telemetry::Telemetry;

mod chain;
mod facilitator;
use crate::facilitator::Facilitator;
mod facilitator_local;
pub mod facilitator_quorum;
mod from_env;
mod handlers;
mod network;
mod provider_cache;
mod sig_down;
mod telemetry;
mod timestamp;
mod types;

/// Initializes the x402 facilitator server.
///
/// - Loads `.env` variables.
/// - Initializes OpenTelemetry tracing.
/// - Connects to Ethereum providers for supported networks.
/// - Starts an Axum HTTP server with the x402 protocol handlers.
///
/// Binds to the address specified by the `HOST` and `PORT` env vars.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load .env variables
    dotenv().ok();

    let telemetry = Telemetry::new()
        .with_name(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .register();

    // Choose facilitator mode: quorum aggregator if QUORUM_PEERS set, else local on-chain
    let http_endpoints = if let Ok(peers_csv) = std::env::var("QUORUM_PEERS") {
        let peers: Vec<String> = peers_csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();

        if !peers.is_empty() {
            let k = std::env::var("QUORUM_K")
                .ok()
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or_else(|| (peers.len() + 1) / 2);

            tracing::info!(peers = %peers_csv, k = k, "Starting quorum facilitator");
            let facilitator = facilitator_quorum::QuorumFacilitator::new(peers, k);
            let axum_state = Arc::new(facilitator);

            async fn post_verify_quorum_handler(
                axum::extract::State(facilitator): axum::extract::State<Arc<facilitator_quorum::QuorumFacilitator>>,
                Json(body): Json<crate::types::VerifyRequest>,
            ) -> impl IntoResponse {
                match facilitator.verify_with_attestations(&body).await {
                    Ok((verify_response, attestations)) => {
                        let mut response = (axum::http::StatusCode::OK, Json(verify_response)).into_response();
                        if let Ok(bytes) = serde_json::to_vec(&attestations) {
                            use base64::Engine;
                            let b64 = base64::engine::general_purpose::STANDARD.encode(bytes);
                            response.headers_mut().insert(
                                "X-Attestations",
                                axum::http::HeaderValue::from_str(&b64).unwrap(),
                            );
                        }
                        response
                    }
                    Err(error) => error.into_response(),
                }
            }

            Router::new()
                .merge(handlers::routes().with_state(axum_state.clone()))
                .route("/verify", axum::routing::post(post_verify_quorum_handler).with_state(axum_state))
                .layer(telemetry.http_tracing())
                .layer(
                    cors::CorsLayer::new()
                        .allow_origin(cors::Any)
                        .allow_methods([Method::GET, Method::POST])
                        .allow_headers(cors::Any),
                )
        } else {
            // Fall back to local facilitator if no peers listed
            let provider_cache = ProviderCache::from_env().await;
            let provider_cache = match provider_cache {
                Ok(provider_cache) => provider_cache,
                Err(e) => {
                    tracing::error!("Failed to create Ethereum providers: {}", e);
                    std::process::exit(1);
                }
            };
            let facilitator = FacilitatorLocal::new(provider_cache);
            let axum_state = Arc::new(facilitator);

            async fn post_attest_local_handler(
                axum::extract::State(facilitator): axum::extract::State<Arc<FacilitatorLocal<ProviderCache>>>,
                Json(body): Json<crate::types::VerifyRequest>,
            ) -> impl IntoResponse {
                let node_id = std::env::var("NODE_ID")
                    .ok()
                    .or_else(|| std::env::var("HOSTNAME").ok())
                    .unwrap_or_else(|| "unknown-node".to_string());

                match facilitator.verify(&body).await {
                    Ok(verify_response) => {
                        let mut attestation = match crate::types::Attestation::from_verify(
                            node_id,
                            &body,
                            verify_response,
                        ) {
                            Ok(a) => a,
                            Err(err) => {
                                return (
                                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                    axum::Json(crate::types::ErrorResponse {
                                        error: format!("failed to build attestation: {}", err),
                                    }),
                                )
                                    .into_response();
                            }
                        };

                        if let Ok(keys) = std::env::var(crate::from_env::ENV_EVM_PRIVATE_KEY) {
                            if let Some(first) = keys.split(',').map(str::trim).find(|s| !s.is_empty()) {
                                if let Ok(signer) = PrivateKeySigner::from_str(first) {
                                    if let Ok(hash) = crate::types::Attestation::signing_hash(&body, &attestation.verify_response) {
                                        match signer.sign_hash(&hash.into()).await {
                                            Ok(sig) => {
                                                attestation.signature = Some(format!("0x{}", hex::encode(sig.as_bytes())));
                                                attestation.signer = Some(crate::types::MixedAddress::Evm(signer.address().into()));
                                            }
                                            Err(_) => {}
                                        }
                                    }
                                }
                            }
                        }

                        (axum::http::StatusCode::OK, axum::Json(attestation)).into_response()
                    }
                    Err(error) => error.into_response(),
                }
            }

            Router::new()
                .merge(handlers::routes().with_state(axum_state.clone()))
                .route("/attest", axum::routing::post(post_attest_local_handler).with_state(axum_state))
                .layer(telemetry.http_tracing())
                .layer(
                    cors::CorsLayer::new()
                        .allow_origin(cors::Any)
                        .allow_methods([Method::GET, Method::POST])
                        .allow_headers(cors::Any),
                )
        }
    } else {
        let provider_cache = ProviderCache::from_env().await;
        // Abort if we can't initialise Ethereum providers early
        let provider_cache = match provider_cache {
            Ok(provider_cache) => provider_cache,
            Err(e) => {
                tracing::error!("Failed to create Ethereum providers: {}", e);
                std::process::exit(1);
            }
        };
        let facilitator = FacilitatorLocal::new(provider_cache);
        let axum_state = Arc::new(facilitator);

        Router::new()
            .merge(handlers::routes().with_state(axum_state))
            .layer(telemetry.http_tracing())
            .layer(
                cors::CorsLayer::new()
                    .allow_origin(cors::Any)
                    .allow_methods([Method::GET, Method::POST])
                    .allow_headers(cors::Any),
            )
    };

    let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(8080);

    let addr = SocketAddr::new(host.parse().expect("HOST must be a valid IP address"), port);
    tracing::info!("Starting server at http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        });

    let sig_down = SigDown::try_new()?;
    let axum_cancellation_token = sig_down.cancellation_token();
    let axum_graceful_shutdown = async move { axum_cancellation_token.cancelled().await };
    axum::serve(listener, http_endpoints)
        .with_graceful_shutdown(axum_graceful_shutdown)
        .await?;

    Ok(())
}
