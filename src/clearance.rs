use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, OsRng};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305, KeyInit, Nonce};
use serde_derive::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Eq, PartialEq, Debug, Clone)]
struct ClearanceToken {
    session_id: Uuid,
    admin: bool,
}

struct Clearance {
    cipher: ChaCha20Poly1305,
}

impl Clearance {
    pub fn new(key: &str) -> Clearance {
        let key = BASE64_STANDARD.decode(key).unwrap();
        let key = GenericArray::from_slice(key.as_ref());
        let cipher = ChaCha20Poly1305::new(key);

        Clearance { cipher }
    }

    fn create_key() -> String {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        BASE64_STANDARD.encode(&key)
    }

    fn create_token(&self, admin: bool) -> String {
        let token = ClearanceToken {
            session_id: Uuid::new_v4(),
            admin
        };

        let data = serde_json::to_string(&token).unwrap();
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng); // 96-bits; unique per message

        let mut res = nonce.to_vec();
        res.append(&mut self.cipher.encrypt(&nonce, data.as_bytes()).unwrap());
        BASE64_STANDARD.encode(&res)
    }

    fn validate_token(&self, token: &str) -> Option<ClearanceToken> {
        let data = BASE64_STANDARD.decode(token).unwrap();

        let nonce = &data[..12];
        let data = self
            .cipher
            .decrypt(Nonce::from_slice(nonce), &data[12..])
            .unwrap();

        let token: ClearanceToken = serde_json::from_slice(&data).unwrap();
        Some(token)
    }
}

#[cfg(test)]
mod tests {
    use crate::clearance::{Clearance, ClearanceToken};
    use uuid::Uuid;

    #[test]
    fn test_token_generation() {
        let key = Clearance::create_key();
        println!("key: {}", key);

        let clearance = Clearance::new(&key);

        let token = clearance.create_token(false);
        println!("token: {}", token);

        clearance.validate_token(&token).unwrap();
    }

    #[test]
    fn test_token() {
        let key = "OI7GEQWM3x63WCZo5sJF6IkIm15NN6q0oRkSyeSyGZQ=";

        let clearance = Clearance::new(&key);

        let token = "tjxWtmNPhybFrzArJdFSR8O5rsDpOEOHGhhCQ4PAcpS1JcpyX0kN7ZUoZBD0Uia0wL5xnMNMyfDz6GM3EFdU+HGciPtCVyv9+sHjjrTu3Mo+u33oeLvtk6V8rDm01mM=";
        let token = clearance.validate_token(&token).unwrap();

        let expected = ClearanceToken {
            session_id: Uuid::parse_str("160d297b-6009-4d5b-90e6-50cb0665091b").unwrap(),
            admin: false,
        };

        assert_eq!(expected, token);
    }
}
