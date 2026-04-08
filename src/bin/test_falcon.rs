use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};
fn main() {
    let (pk, sk) = pqcrypto_falcon::falcon512::keypair();
    let msg = b"hello";
    let sig = pqcrypto_falcon::falcon512::detached_sign(msg, &sk);
    let ok = pqcrypto_falcon::falcon512::verify_detached_signature(&sig, msg, &pk);
    println!("OK: {:?}", ok.is_ok());
}
