use crate::errors::DoHError;
use hpke::kex::Serializable;
use odoh_rs::key_utils::{derive_keypair_from_seed};
use odoh_rs::protocol::{create_response_msg, 
    parse_received_query, RESPONSE_NONCE_SIZE, 
    ObliviousDoHQueryBody, Serialize, 
    ObliviousDoHKeyPair, ObliviousDoHConfigContents, 
    ObliviousDoHConfig, ObliviousDoHConfigs
};
use rand::Rng;
use std::fmt;

// https://cfrg.github.io/draft-irtf-cfrg-hpke/draft-irtf-cfrg-hpke.html#name-algorithm-identifiers
const DEFAULT_HPKE_SEED_SIZE: usize = 32;
const DEFAULT_HPKE_KEM: u16 = 0x0020; // DHKEM(X25519, HKDF-SHA256)
const DEFAULT_HPKE_KDF: u16 = 0x0001; // KDF(SHA-256)
const DEFAULT_HPKE_AEAD: u16 = 0x0001; // AEAD(AES-GCM-128)

#[derive(Clone)]
pub struct ODoHPublicKey {
    key: ObliviousDoHKeyPair,
    serialized_configs: Vec<u8>,
}

impl fmt::Debug for ODoHPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ODoHPublicKey").finish()
    }
}

#[derive(Clone, Debug)]
pub struct ODoHQueryContext {
    query: ObliviousDoHQueryBody,
    secret: Vec<u8>,
}

fn generate_key_pair() -> ObliviousDoHKeyPair {
    let ikm = rand::thread_rng().gen::<[u8; DEFAULT_HPKE_SEED_SIZE]>();
    let (secret_key, public_key) = derive_keypair_from_seed(&ikm);
    let public_key_bytes = public_key.to_bytes().to_vec();
    let odoh_public_key = ObliviousDoHConfigContents {
        kem_id: DEFAULT_HPKE_KEM,  
        kdf_id: DEFAULT_HPKE_KDF,  
        aead_id: DEFAULT_HPKE_AEAD, 
        public_key: public_key_bytes,
    };
    ObliviousDoHKeyPair {
        private_key: secret_key,
        public_key: odoh_public_key,
    }
}

impl ODoHPublicKey {    
    pub fn new() -> Result<ODoHPublicKey, DoHError> {
        let key_pair = generate_key_pair();
        let config = ObliviousDoHConfig::new(&key_pair.public_key.clone().to_bytes().unwrap()).unwrap();
        let serialized_configs = ObliviousDoHConfigs {
            configs: vec![config.clone()],
        }
        .to_bytes()
        .unwrap()
        .to_vec();

        Ok(ODoHPublicKey{
            key: key_pair,
            serialized_configs: serialized_configs
        })
    }

    pub fn config(self) -> Vec<u8> {
        self.serialized_configs
    }

    pub async fn decrypt_query(self, encrypted_query: Vec<u8>) -> Result<(Vec<u8>, ODoHQueryContext), DoHError> {
        let (query, server_secret) = match parse_received_query(&self.key, &encrypted_query).await {
            Ok((pq, ss)) => (pq, ss),
            Err(_) => return Err(DoHError::InvalidData)
        };
        let context = ODoHQueryContext{
            query: query.clone(),
            secret: server_secret,
        };
        Ok((query.dns_msg.clone(), context))
    }
}

impl ODoHQueryContext {
    pub async fn encrypt_response(self, response_body: Vec<u8>) -> Result<Vec<u8>, DoHError> {
        let response_nonce = rand::thread_rng().gen::<[u8; RESPONSE_NONCE_SIZE]>();
        create_response_msg(&self.secret, &response_body, None, Some(response_nonce.to_vec()), &self.query)
            .await
            .map_err(|_| {
                DoHError::InvalidData
            })
    }
}