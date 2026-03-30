use anyhow::Result;
use pqcrypto_dilithium::dilithium3::keypair;
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use std::fs;
use std::path::PathBuf;

fn main() -> Result<()> {
    let keys_dir = PathBuf::from("keys");
    fs::create_dir_all(&keys_dir)?;

    let (pk, sk) = keypair();

    let pk_path = keys_dir.join("dilithium_pk.bin");
    let sk_path = keys_dir.join("dilithium_sk.bin");

    fs::write(&pk_path, pk.as_bytes())?;
    fs::write(&sk_path, sk.as_bytes())?;

    println!(
        "✓ Dilithium3 keypair generated:\n  pk: {}\n  sk: {}",
        pk_path.display(),
        sk_path.display()
    );
    Ok(())
}
