use crate::facilitator::Facilitator;
use crate::types::{
    Attestation, ErrorResponse, FacilitatorErrorReason, SettleRequest, SettleResponse,
    SupportedPaymentKind, SupportedPaymentKindsResponse, VerifyRequest, VerifyResponse,
};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use futures::future::join_all;
use alloy::primitives::keccak256;
use alloy::hex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Clone)]
pub struct QuorumFacilitator {
    peers: Vec<String>,
    quorum_k: usize,
    http: Client,
}

impl QuorumFacilitator {
    pub fn new<T: Into<String>>(peers: Vec<T>, quorum_k: usize) -> Self {
        let peers = peers.into_iter().map(Into::into).collect();
        let http = Client::new();
        Self {
            peers,
            quorum_k,
            http,
        }
    }

    fn ensure_quorum(&self) -> Result<(), QuorumError> {
        if self.peers.is_empty() {
            return Err(QuorumError::NoPeers);
        }
        if self.quorum_k == 0 || self.quorum_k > self.peers.len() {
            return Err(QuorumError::InvalidQuorum);
        }
        Ok(())
    }

    pub async fn verify_with_attestations(
        &self,
        request: &VerifyRequest,
    ) -> Result<(VerifyResponse, Vec<Attestation>), QuorumError> {
        self.ensure_quorum()?;

        let body = serde_json::to_value(request).map_err(|e| QuorumError::Http(e.to_string()))?;
        let body = std::sync::Arc::new(body);
        let futures = self.peers.iter().map(|peer| {
            let http = self.http.clone();
            let url = format!("{}/attest", peer.trim_end_matches('/'));
            let body = body.clone();
            async move {
                let res = http.post(url).json(&body).send().await;
                match res {
                    Ok(resp) => resp.json::<Attestation>().await.map_err(|e| e.to_string()),
                    Err(err) => Err(err.to_string()),
                }
            }
        });

        let results = join_all(futures).await;

        let req_bytes = serde_json::to_vec(request).map_err(|e| QuorumError::Http(e.to_string()))?;
        let expected_hash = format!("0x{}", hex::encode(keccak256(&req_bytes)));

        let mut valid_counts: HashMap<String, usize> = HashMap::new();
        let mut invalid_reasons: HashMap<String, usize> = HashMap::new();
        let mut any_invalid_with_payer: Option<String> = None;
        let mut attestations: Vec<Attestation> = vec![];

        for att in results.into_iter().flatten() {
            let matches = att.request_hash == expected_hash;
            if matches {
                match &att.verify_response {
                    VerifyResponse::Valid { payer } => {
                        let key = payer.to_string();
                        *valid_counts.entry(key).or_insert(0) += 1;
                    }
                    VerifyResponse::Invalid { reason, payer } => {
                        let key = format!("{:?}", reason);
                        *invalid_reasons.entry(key).or_insert(0) += 1;
                        if any_invalid_with_payer.is_none() {
                            any_invalid_with_payer = payer.as_ref().map(|p| p.to_string());
                        }
                    }
                }
            }
            attestations.push(att);
        }

        let selected = valid_counts
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .filter(|(_, c)| *c >= self.quorum_k)
            .map(|(payer, _)| payer);

        if let Some(payer_str) = selected {
            let payer = crate::types::MixedAddress::deserialize(serde_json::Value::String(payer_str))
                .map_err(|e| QuorumError::Http(e.to_string()))?;
            return Ok((VerifyResponse::valid(payer), attestations));
        }

        let reason = invalid_reasons
            .into_iter()
            .max_by_key(|(_, c)| *c)
            .map(|(s, _)| FacilitatorErrorReason::FreeForm(s))
            .unwrap_or(FacilitatorErrorReason::FreeForm("no_consensus".to_string()));

        let payer = match any_invalid_with_payer {
            Some(s) => crate::types::MixedAddress::deserialize(serde_json::Value::String(s)).ok(),
            None => None,
        };
        Ok((VerifyResponse::invalid(payer, reason), attestations))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum QuorumError {
    #[error("quorum: no peers configured")]
    NoPeers,
    #[error("quorum: invalid k")]
    InvalidQuorum,
    #[error("http: {0}")]
    Http(String),
}

impl IntoResponse for QuorumError {
    fn into_response(self) -> Response {
        let status = match self {
            QuorumError::NoPeers | QuorumError::InvalidQuorum => StatusCode::INTERNAL_SERVER_ERROR,
            QuorumError::Http(_) => StatusCode::BAD_GATEWAY,
        };

        (
            status,
            axum::Json(ErrorResponse {
                error: self.to_string(),
            }),
        )
            .into_response()
    }
}

#[derive(Serialize, Deserialize)]
struct SupportedResponseWrapper {
    kinds: Vec<SupportedPaymentKind>,
}

impl Facilitator for QuorumFacilitator {
    type Error = QuorumError;

    fn verify(
        &self,
        request: &VerifyRequest,
    ) -> impl std::future::Future<Output = Result<VerifyResponse, Self::Error>> + Send {
        let this = self.clone();
        let request = request.clone();
        async move {
            this.ensure_quorum()?;
            let body = serde_json::to_value(&request)
                .map_err(|e| QuorumError::Http(e.to_string()))?;
            let body = std::sync::Arc::new(body);
            let futures = this.peers.iter().map(|peer| {
                let http = this.http.clone();
                let url = format!("{}/attest", peer.trim_end_matches('/'));
                let body = body.clone();
                async move {
                    let res = http.post(url).json(&body).send().await;
                    match res {
                        Ok(resp) => resp
                            .json::<Attestation>()
                            .await
                            .map_err(|e| e.to_string()),
                        Err(err) => Err(err.to_string()),
                    }
                }
            });

            let results = join_all(futures).await;

            // Compute local request hash for attestation verification
            let req_bytes = serde_json::to_vec(&request)
                .map_err(|e| QuorumError::Http(e.to_string()))?;
            let expected_hash = format!("0x{}", hex::encode(keccak256(&req_bytes)));

            let mut valid_counts: HashMap<String, usize> = HashMap::new();
            let mut invalid_reasons: HashMap<String, usize> = HashMap::new();
            let mut any_invalid_with_payer: Option<String> = None;

            for att in results.into_iter().flatten() {
                // Discard attestations that don't match the computed request hash
                if att.request_hash != expected_hash {
                    *invalid_reasons
                        .entry("bad_attestation_hash".to_string())
                        .or_insert(0) += 1;
                    continue;
                }
                match att.verify_response {
                    VerifyResponse::Valid { payer } => {
                        let key = payer.to_string();
                        *valid_counts.entry(key).or_insert(0) += 1;
                    }
                    VerifyResponse::Invalid { reason, payer } => {
                        let key = format!("{:?}", reason);
                        *invalid_reasons.entry(key).or_insert(0) += 1;
                        if any_invalid_with_payer.is_none() {
                            any_invalid_with_payer = payer.map(|p| p.to_string());
                        }
                    }
                }
            }

            // Choose the most frequent valid payer
            let selected = valid_counts
                .into_iter()
                .max_by_key(|(_, c)| *c)
                .filter(|(_, c)| *c >= this.quorum_k)
                .map(|(payer, _)| payer);

            if let Some(payer_str) = selected {
                // Deserialize payer back from string via Display of MixedAddress
                let payer = crate::types::MixedAddress::deserialize(
                    serde_json::Value::String(payer_str),
                )
                .map_err(|e| QuorumError::Http(e.to_string()))?;
                return Ok(VerifyResponse::valid(payer));
            }

            // Aggregate invalid reasons
            let reason = invalid_reasons
                .into_iter()
                .max_by_key(|(_, c)| *c)
                .map(|(s, _)| FacilitatorErrorReason::FreeForm(s))
                .unwrap_or(FacilitatorErrorReason::FreeForm("no_consensus".to_string()));

            let payer = match any_invalid_with_payer {
                Some(s) => crate::types::MixedAddress::deserialize(serde_json::Value::String(s))
                    .ok(),
                None => None,
            };
            Ok(VerifyResponse::invalid(payer, reason))
        }
    }

    fn settle(
        &self,
        request: &SettleRequest,
    ) -> impl std::future::Future<Output = Result<SettleResponse, Self::Error>> + Send {
        let this = self.clone();
        let request = request.clone();
        async move {
            this.ensure_quorum()?;
            // Deterministically select a single peer to settle to avoid duplicate broadcasts
            let req_bytes = serde_json::to_vec(&request)
                .map_err(|e| QuorumError::Http(e.to_string()))?;
            let h = keccak256(&req_bytes);
            let idx = (h[0] as usize) % this.peers.len();
            let peer = this.peers[idx].trim_end_matches('/').to_string();

            let url = format!("{}/settle", peer);
            let res = this.http.post(url).json(&request).send().await;
            match res {
                Ok(resp) => resp
                    .json::<SettleResponse>()
                    .await
                    .map_err(|e| QuorumError::Http(e.to_string())),
                Err(err) => Err(QuorumError::Http(err.to_string())),
            }
        }
    }

    fn supported(
        &self,
    ) -> impl std::future::Future<Output = Result<SupportedPaymentKindsResponse, Self::Error>> + Send
    {
        let this = self.clone();
        async move {
            this.ensure_quorum()?;
            let futures = this.peers.iter().map(|peer| {
                let http = this.http.clone();
                let url = format!("{}/supported", peer.trim_end_matches('/'));
                async move {
                    let res = http.get(url).send().await;
                    match res {
                        Ok(resp) => resp
                            .json::<SupportedPaymentKindsResponse>()
                            .await
                            .map_err(|e| e.to_string()),
                        Err(err) => Err(err.to_string()),
                    }
                }
            });
            let results = join_all(futures).await;

            let mut kinds = vec![];
            for r in results.into_iter().flatten() {
                kinds.extend(r.kinds);
            }
            Ok(SupportedPaymentKindsResponse { kinds })
        }
    }
}


