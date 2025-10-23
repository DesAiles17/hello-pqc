use pqcrypto_mldsa::mldsa44::*;

fn main() {
    let msg = b"hello from ML-DSA-44";
    let (pk, sk) = keypair();
    let sig = detached_sign(msg, &sk);
    verify_detached_signature(&sig, msg, &pk).expect("verify ok");
    println!(
        "ML-DSA-44 sign/verify OK; pk={}B sig={}B",
        public_key_bytes(),
        signature_bytes()
    );
}
