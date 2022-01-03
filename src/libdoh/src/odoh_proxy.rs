use crate::constants::*;
use crate::errors::DoHError;
use hyper::http::StatusCode;
use reqwest::header;
use urlencoding::decode;

pub fn target_uri_from_query_string(http_query: &str) -> Option<String> {
    let mut targethost = None;
    let mut targetpath = None;
    for parts in http_query.split('&') {
        let mut kv = parts.split('=');
        if let Some(k) = kv.next() {
            match k {
                ODOH_TARGET_HOST_QUERY_PARAM => {
                    targethost = kv.next().map(str::to_string);
                }
                ODOH_TARGET_PATH_QUERY_PARAM => {
                    targetpath = kv.next().map(str::to_string);
                }
                _ => (),
            }
        }
    }
    if let (Some(host), Some(path)) = (targethost, targetpath) {
        // remove percent encoding
        Some(
            decode(&format!("https://{}{}", host, path))
                .unwrap_or(std::borrow::Cow::Borrowed(""))
                .to_string(),
        )
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub struct ODoHProxy {
    client: reqwest::Client,
}

impl ODoHProxy {
    pub fn new(timeout: std::time::Duration) -> Result<Self, DoHError> {
        // build client
        let mut headers = header::HeaderMap::new();
        let ct = "application/oblivious-dns-message";
        headers.insert("Accept", header::HeaderValue::from_str(&ct).unwrap());
        headers.insert("Content-Type", header::HeaderValue::from_str(&ct).unwrap());
        headers.insert(
            "Cache-Control",
            header::HeaderValue::from_str("no-cache, no-store").unwrap(),
        );

        let client = reqwest::Client::builder()
            .user_agent(format!("odoh-proxy/{}", env!("CARGO_PKG_VERSION")))
            .timeout(timeout)
            .trust_dns(true)
            .default_headers(headers)
            .build()
            .map_err(|e| DoHError::Reqwest(e))?;

        Ok(ODoHProxy { client })
    }

    pub async fn forward_to_target(
        &self,
        encrypted_query: &Vec<u8>,
        target_uri: &str,
    ) -> Result<Vec<u8>, StatusCode> {
        // Only post method is allowed in ODoH
        let response = self
            .client
            .post(target_uri)
            .body(encrypted_query.clone())
            .send()
            .await
            .map_err(|e| {
                eprintln!("[ODoH Proxy] Upstream query error: {}", e);
                DoHError::Reqwest(e)
            })?;

        if response.status() != reqwest::StatusCode::OK {
            eprintln!("[ODoH Proxy] Response not ok: {:?}", response.status());
            return Err(response.status());
        }

        let body = response.bytes().await.map_err(|e| DoHError::Reqwest(e))?;
        Ok(body.to_vec())
    }
}
