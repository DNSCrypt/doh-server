use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use odoh_rs::{
    Deserialize, ObliviousDoHConfig, ObliviousDoHConfigs, ObliviousDoHKeyPair, ObliviousDoHMessage,
    ObliviousDoHMessagePlaintext, OdohSecret, ResponseNonce, Serialize,
};
use rand::Rng;
use tokio::runtime;

use crate::constants::ODOH_KEY_ROTATION_SECS;
use crate::errors::DoHError;

#[derive(Clone)]
pub struct ODoHPublicKey {
    key_pair: ObliviousDoHKeyPair,
    serialized_configs: Vec<u8>,
}

impl fmt::Debug for ODoHPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ODoHPublicKey").finish()
    }
}

#[derive(Clone, Debug)]
pub struct ODoHQueryContext {
    query: ObliviousDoHMessagePlaintext,
    server_secret: OdohSecret,
}

impl ODoHPublicKey {
    pub fn new() -> Result<ODoHPublicKey, DoHError> {
        let key_pair = ObliviousDoHKeyPair::new(&mut rand::thread_rng());
        let config = ObliviousDoHConfig::from(key_pair.public().clone());
        let mut serialized_configs = Vec::new();
        ObliviousDoHConfigs::from(vec![config])
            .serialize(&mut serialized_configs)
            .map_err(|e| DoHError::ODoHConfigError(e.into()))?;
        Ok(ODoHPublicKey {
            key_pair,
            serialized_configs,
        })
    }

    pub fn into_config(self) -> Vec<u8> {
        self.serialized_configs
    }

    pub fn decrypt_query(
        self,
        encrypted_query: Vec<u8>,
    ) -> Result<(Vec<u8>, ODoHQueryContext), DoHError> {
        let odoh_query = ObliviousDoHMessage::deserialize(&mut bytes::Bytes::from(encrypted_query))
            .map_err(|_| DoHError::InvalidData)?;
        match self.key_pair.public().identifier() {
            Ok(key_id) => {
                if !key_id.eq(&odoh_query.key_id()) {
                    return Err(DoHError::StaleKey);
                }
            }
            Err(_) => return Err(DoHError::InvalidData),
        };
        let (query, server_secret) = match odoh_rs::decrypt_query(&odoh_query, &self.key_pair) {
            Ok((pq, ss)) => (pq, ss),
            Err(_) => return Err(DoHError::InvalidData),
        };
        let context = ODoHQueryContext {
            query: query.clone(),
            server_secret,
        };
        Ok((query.into_msg().to_vec(), context))
    }
}

impl ODoHQueryContext {
    pub fn encrypt_response(self, response_body: Vec<u8>) -> Result<Vec<u8>, DoHError> {
        let response_nonce = rand::thread_rng().gen::<ResponseNonce>();
        let response_body_ = ObliviousDoHMessagePlaintext::new(response_body, 0);
        let encrypted_response = odoh_rs::encrypt_response(
            &self.query,
            &response_body_,
            self.server_secret,
            response_nonce,
        )
        .map_err(|_| DoHError::InvalidData)?;
        let mut encrypted_response_bytes = Vec::new();
        encrypted_response
            .serialize(&mut encrypted_response_bytes)
            .map_err(|_| DoHError::InvalidData)?;
        Ok(encrypted_response_bytes)
    }
}

#[derive(Clone, Debug)]
pub struct ODoHRotator {
    key: Arc<ArcSwap<ODoHPublicKey>>,
}

impl ODoHRotator {
    pub fn new(runtime_handle: runtime::Handle) -> Result<ODoHRotator, DoHError> {
        let public_key = match ODoHPublicKey::new() {
            Ok(key) => Arc::new(ArcSwap::from_pointee(key)),
            Err(e) => panic!("ODoH key rotation error: {}", e),
        };

        let current_key = Arc::clone(&public_key);

        runtime_handle.spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(ODOH_KEY_ROTATION_SECS.into())).await;
                match ODoHPublicKey::new() {
                    Ok(key) => {
                        current_key.store(Arc::new(key));
                    }
                    Err(e) => eprintln!("ODoH key rotation error: {}", e),
                };
            }
        });

        Ok(ODoHRotator {
            key: Arc::clone(&public_key),
        })
    }

    pub fn current_public_key(&self) -> Arc<ODoHPublicKey> {
        let key = Arc::clone(&self.key);
        Arc::clone(&key.load())
    }
}
