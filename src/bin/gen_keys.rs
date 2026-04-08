use anyhow::{anyhow, Result};
use clap::Parser;
use fips204::ml_dsa_65;
use fips204::traits::SerDes as MlDsaSerDes;
use fips205::slh_dsa_shake_128s;
use fips205::traits::SerDes as SlhDsaSerDes;
use p256::ecdsa::SigningKey;
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{PublicKey, SecretKey};
use std::fs;
use std::path::{Path, PathBuf};

const SUPPORTED_ALGORITHMS: [&str; 4] = ["ml_dsa", "slh_dsa", "fn_dsa", "ecdsa"];

#[derive(Parser, Debug)]
#[command(name = "gen-keys")]
#[command(about = "Generate PQC key material used by the project")]
struct Cli {
    #[arg(long, value_delimiter = ',', default_value = "all")]
    algorithms: Vec<String>,

    #[arg(long, default_value = "keys")]
    keys_dir: PathBuf,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let algorithms = resolve_algorithms(&cli.algorithms)?;

    fs::create_dir_all(&cli.keys_dir)?;

    println!(
        "Generating Rust-managed key material into {}...",
        cli.keys_dir.display()
    );
    for (index, algorithm) in algorithms.iter().enumerate() {
        println!("{}/{} {}", index + 1, algorithms.len(), algorithm);
        match *algorithm {
            "ml_dsa" => generate_ml_dsa(&cli.keys_dir)?,
            "slh_dsa" => generate_slh_dsa(&cli.keys_dir)?,
            "fn_dsa" => generate_fn_dsa(&cli.keys_dir)?,
            "ecdsa" => generate_ecdsa(&cli.keys_dir)?,
            other => return Err(anyhow!("Unsupported algorithm '{}'", other)),
        }
    }

    Ok(())
}

fn resolve_algorithms(values: &[String]) -> Result<Vec<&'static str>> {
    let requested = if values.is_empty() {
        vec!["all".to_string()]
    } else {
        values.to_vec()
    };

    if requested
        .iter()
        .any(|value| value.trim().eq_ignore_ascii_case("all"))
    {
        return Ok(SUPPORTED_ALGORITHMS.to_vec());
    }

    let mut resolved = Vec::new();
    for raw in requested {
        let normalized =
            normalize_algorithm(&raw).ok_or_else(|| anyhow!("Unsupported algorithm '{}'", raw))?;
        if !resolved.contains(&normalized) {
            resolved.push(normalized);
        }
    }

    if resolved.is_empty() {
        return Err(anyhow!(
            "No supported algorithms selected. Use one of: {}",
            SUPPORTED_ALGORITHMS.join(", ")
        ));
    }

    Ok(resolved)
}

fn normalize_algorithm(input: &str) -> Option<&'static str> {
    match input.trim().to_ascii_lowercase().as_str() {
        "ml_dsa" | "mldsa" | "ml_dsa_65" => Some("ml_dsa"),
        "slh_dsa" | "slh-dsa" | "slhdsa" | "slh_dsa_shake_128s" => Some("slh_dsa"),
        "fn_dsa" | "fn-dsa" | "falcon512" => Some("fn_dsa"),
        "ecdsa" | "ecdsa_p256" | "p256" => Some("ecdsa"),
        _ => None,
    }
}

fn generate_ecdsa(keys_dir: &Path) -> Result<()> {
    let sk = SigningKey::random(&mut rand::thread_rng());
    let pk = sk.verifying_key();
    write_keypair(
        keys_dir,
        "ECDSA P-256",
        "ecdsa_pk.bin",
        pk.to_sec1_bytes().as_ref(),
        "ecdsa_sk.bin",
        sk.to_bytes().as_ref(),
    )
}

fn generate_ml_dsa(keys_dir: &Path) -> Result<()> {
    let (pk, sk) = ml_dsa_65::try_keygen().map_err(|e| anyhow!("{:?}", e))?;
    write_keypair(
        keys_dir,
        "ML-DSA-65 (FIPS 204)",
        "ml_dsa_pk.bin",
        &pk.into_bytes(),
        "ml_dsa_sk.bin",
        &sk.into_bytes(),
    )
}

fn generate_slh_dsa(keys_dir: &Path) -> Result<()> {
    let (pk, sk) = slh_dsa_shake_128s::try_keygen().map_err(|e| anyhow!("{:?}", e))?;
    write_keypair(
        keys_dir,
        "SLH-DSA-SHAKE-128s (FIPS 205)",
        "slh_dsa_pk.bin",
        &pk.into_bytes(),
        "slh_dsa_sk.bin",
        &sk.into_bytes(),
    )
}

fn generate_fn_dsa(keys_dir: &Path) -> Result<()> {
    let (pk, sk) = falcon512::keypair();
    write_keypair(
        keys_dir,
        "FN-DSA-512",
        "fn_dsa_pk.bin",
        pk.as_bytes(),
        "fn_dsa_sk.bin",
        sk.as_bytes(),
    )
}

fn write_keypair(
    keys_dir: &Path,
    label: &str,
    public_name: &str,
    public_bytes: &[u8],
    secret_name: &str,
    secret_bytes: &[u8],
) -> Result<()> {
    let public_path = keys_dir.join(public_name);
    let secret_path = keys_dir.join(secret_name);

    fs::write(&public_path, public_bytes)?;
    fs::write(&secret_path, secret_bytes)?;

    println!(
        "  {} keypair generated:\n    pk: {}\n    sk: {}",
        label,
        public_path.display(),
        secret_path.display()
    );

    Ok(())
}
