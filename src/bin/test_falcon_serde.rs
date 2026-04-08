use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use pqcrypto_falcon::falcon512::{self, DetachedSignature, PublicKey, SecretKey};
fn main() {
    let (pk, sk) = falcon512::keypair();
    
    let pk_bytes = pk.as_bytes();
    let pk2 = PublicKey::from_bytes(pk_bytes).unwrap();
    
    let sk_bytes = sk.as_bytes();
    let sk2 = SecretKey::from_bytes(sk_bytes).unwrap();
    
    let msg = b"test message";
    let sig = falcon512::detached_sign(msg, &sk2);
    
    let sig_bytes = sig.as_bytes();
    let sig2 = DetachedSignature::from_bytes(sig_bytes).unwrap();
    
    let ok = falcon512::verify_detached_signature(&sig2, msg, &pk2);
    println!("OK: {:?}", ok.is_ok());
}
