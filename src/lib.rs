use rand::thread_rng;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

// Expose all your existing files
pub mod decrypt;
pub mod encrypt;
pub mod gka;
pub mod keygen;
pub mod ndcrypt;
pub mod params;

#[wasm_bindgen]
pub struct NDCryptWasm {
    pk: Option<keygen::PublicKey>,
    sk: Option<keygen::PrivateKey>,
    shared_seed: Option<Zeroizing<[u8; 32]>>,
}

#[wasm_bindgen]
impl NDCryptWasm {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        NDCryptWasm {
            pk: None,
            sk: None,
            shared_seed: None,
        }
    }

    // User 1 calls this to generate keys. Returns A and B flattened into a 2048-element array
    pub fn generate_keys(&mut self) -> Vec<u16> {
        let mut rng = thread_rng();
        let (pk, sk) = keygen::generate_keypair(&mut rng);

        let mut result = Vec::with_capacity(2048);
        result.extend_from_slice(&pk.a.coeffs);
        result.extend_from_slice(&pk.b.coeffs);

        self.pk = Some(pk);
        self.sk = Some(sk);
        return result;
    }

    // User 2 receives User 1's key, encapsulates a seed, returns C1 and C2 flattened into 2048 elements
    pub fn encapsulate_seed(&mut self, pubkey_flat: &[u16]) -> Vec<u16> {
        if self.shared_seed.is_some() {
            return vec![];
        }
        if pubkey_flat.len() != 2048 {
            return vec![];
        }

        let mut a_coeffs = [0u16; 1024];
        let mut b_coeffs = [0u16; 1024];
        a_coeffs.copy_from_slice(&pubkey_flat[0..1024]);
        b_coeffs.copy_from_slice(&pubkey_flat[1024..2048]);

        let pk = keygen::PublicKey {
            a: gka::RingElement { coeffs: a_coeffs },
            b: gka::RingElement { coeffs: b_coeffs },
        };

        let mut rng = thread_rng();
        let enc_result = encrypt::encapsulate_payload(&pk, &mut rng);

        self.shared_seed = Some(Zeroizing::new(*enc_result.shared_seed));

        let mut result = Vec::with_capacity(2048);
        result.extend_from_slice(&enc_result.ciphertext.c1.coeffs);
        result.extend_from_slice(&enc_result.ciphertext.c2.coeffs);
        return result;
    }

    // User 1 receives user 2's ciphertext and decapsulates to recover the seed
    pub fn decapsulate_seed(&mut self, cipher_flat: &[u16]) -> bool {
        if self.shared_seed.is_some() {
            return false;
        }
        if cipher_flat.len() != 2048 {
            return false;
        }

        if let (Some(sk), Some(pk)) = (&self.sk, &self.pk) {
            let mut c1_coeffs = [0u16; 1024];
            let mut c2_coeffs = [0u16; 1024];
            c1_coeffs.copy_from_slice(&cipher_flat[0..1024]);
            c2_coeffs.copy_from_slice(&cipher_flat[1024..2048]);

            let ciphertext = encrypt::Ciphertext {
                c1: gka::RingElement { coeffs: c1_coeffs },
                c2: gka::RingElement { coeffs: c2_coeffs },
            };

            // FO re-encryption check happens inside decapsulate_payload. A forged
            // or corrupted ciphertext returns Err here — we must not set
            // shared_seed or report success in that case (Bug #1 regression guard).
            match decrypt::decapsulate_payload(&ciphertext, sk, pk) {
                Ok(dec_result) => {
                    self.shared_seed = Some(Zeroizing::new(*dec_result.shared_seed));
                    return true;
                }
                Err(_) => {
                    return false;
                }
            }
        }
        return false;
    }

    // Derive a deterministic starting nonce from the shared seed
    pub fn get_nonce_base(&self, party_index: u8) -> u32 {
        use sha3::{Digest, Sha3_256};

        if let Some(seed) = &self.shared_seed {
            let mut hasher = Sha3_256::new();
            hasher.update([0x05]);
            hasher.update([party_index]);
            hasher.update(seed.as_ref());
            let digest = hasher.finalize();
            return u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
        } else {
            return 0;
        }
    }
    // Encrypt raw bytes. Caller builds the full framed payload before passing it in.
    // Returns 1040 u16s: 1024 ciphertext coefficients + 16 MAC tag words.
    pub fn encrypt_bytes(&self, payload: &[u8], nonce: u32) -> Vec<u16> {
        if let Some(seed) = &self.shared_seed {
            if let Ok(out) = ndcrypt::encrypt_authenticated(payload, &**seed, nonce as u64) {
                return out;
            }
        }
        vec![]
    }

    // Encrypt raw bytes and bind caller-supplied authenticated metadata.
    // The metadata is not encrypted, but any change to it makes decryption fail.
    pub fn encrypt_bytes_aad(
        &self,
        payload: &[u8],
        nonce: u32,
        aad: &[u8],
    ) -> Result<Vec<u16>, JsValue> {
        if let Some(seed) = &self.shared_seed {
            return ndcrypt::encrypt_authenticated_with_aad(payload, &**seed, nonce as u64, aad)
                .map_err(|e| JsValue::from_str(&format!("{:?}", e)));
        }
        Err(JsValue::from_str("MissingSharedSeed"))
    }

    // Decrypt a 1040-u16 authenticated ciphertext (1024 coefficients + 16 MAC tag words)
    // back to raw bytes.  Returns an empty Vec on MAC failure, wrong seed, or bad length.
    pub fn decrypt_bytes(&self, cipher: &[u16], nonce: u32) -> Vec<u8> {
        if cipher.len() != 1040 {
            return vec![];
        }
        if let Some(seed) = &self.shared_seed {
            if let Ok(bytes) = ndcrypt::decrypt_authenticated(cipher, &**seed, nonce as u64) {
                return bytes;
            }
        }
        vec![]
    }

    // Decrypt bytes with authenticated metadata. Unlike decrypt_bytes(), this
    // reports failures explicitly so callers can distinguish tampering from a
    // valid empty plaintext.
    pub fn decrypt_bytes_aad(
        &self,
        cipher: &[u16],
        nonce: u32,
        aad: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        if let Some(seed) = &self.shared_seed {
            return ndcrypt::decrypt_authenticated_with_aad(cipher, &**seed, nonce as u64, aad)
                .map_err(|e| JsValue::from_str(&format!("{:?}", e)));
        }
        Err(JsValue::from_str("MissingSharedSeed"))
    }

    // Backwards-compatible wrappers
    pub fn encrypt_msg(&self, msg: &str, nonce: u32) -> Vec<u16> {
        return self.encrypt_bytes(msg.as_bytes(), nonce);
    }

    pub fn decrypt_msg(&self, cipher: &[u16], nonce: u32) -> String {
        let bytes = self.decrypt_bytes(cipher, nonce);
        return String::from_utf8(bytes).unwrap_or_else(|_| String::new());
    }
}
