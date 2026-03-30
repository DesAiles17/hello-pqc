use pqcrypto_dilithium::dilithium3::keypair;
use std::fs;

fn main() {
    let (_pk, sk) = keypair();
    fs::write("keys/dilithium_sk.bin", sk.as_bytes()).unwrap();
    println!("Dilithium secret key generated: keys/dilithium_sk.bin");
}
