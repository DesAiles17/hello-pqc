use pqcrypto_falcon::falcon512::*;

fn main() {
    let msg = b"hello from Falcon-512";
    let (pk, sk) = keypair();
    let sig = detached_sign(msg, &sk);
    verify_detached_signature(&sig, msg, &pk).expect("verify ok");
    println!(
        "Falcon-512 sign/verify OK; pk={}B sig={}B",
        public_key_bytes(),
        signature_bytes()
    );
}
