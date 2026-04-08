use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use pqcrypto_falcon::falcon512::{self, DetachedSignature, PublicKey, SecretKey};

fn main() {
    let (pk, sk) = falcon512::keypair();
    let msg = b"test message";
    let sig = falcon512::detached_sign(msg, &sk);
    
    let sig_b64 = STANDARD_NO_PAD.encode(sig.as_bytes());
    
    let sig_bytes = STANDARD_NO_PAD.decode(&sig_b64).unwrap();
    let sig2 = DetachedSignature::from_bytes(&sig_bytes).unwrap();
    
    let ok = falcon512::verify_detached_signature(&sig2, msg, &pk);
    println!("OK: {:?}", ok.is_ok());
}
