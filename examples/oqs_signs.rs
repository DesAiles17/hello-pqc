use oqs::sig::{Algorithm, Sig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    oqs::init();
    for alg in [Algorithm::MlDsa44, Algorithm::Falcon512] {
        let sigalg = Sig::new(alg)?;
        let (pk, sk) = sigalg.keypair()?;
        let msg = b"hello via OQS";
        let sig = sigalg.sign(msg, &sk)?;
        sigalg.verify(msg, &sig, &pk)?;
        println!("{alg:?} sign/verify OK");
    }
    Ok(())
}
