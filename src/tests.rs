use ark_std::test_rng;
use halo2curves::{
    bn256,
    ff::FromUniformBytes,
    group::{cofactor::CofactorGroup, Curve},
    grumpkin, secp256k1,
    serde::SerdeObject,
    CurveExt,
};

use crate::VRFKeypair;

#[test]
fn test_serialization() {
    test_serialization_helper::<bn256::G1>();
    test_serialization_helper::<grumpkin::G1>();
    test_serialization_helper::<secp256k1::Secp256k1>();
}

fn test_serialization_helper<C>()
where
    C::Scalar: FromUniformBytes<64> + SerdeObject,
    C: Curve,
    C::AffineRepr: SerdeObject,
{
    let mut rng = test_rng();
    let keypair = VRFKeypair::<C>::random(&mut rng);
    let keypair_bytes = keypair.to_raw_bytes();
    let sk_bytes = keypair.private_key.to_raw_bytes();
    let pk_bytes = keypair.public_key.to_raw_bytes();

    println!("{} {:?}", keypair_bytes.len(), keypair_bytes);
    println!("{} {:?}", keypair_bytes.len(), sk_bytes);
    println!("{} {:?}", keypair_bytes.len(), pk_bytes);
}

#[test]
fn test_vrf() {
    test_vrf_helper::<bn256::G1>();
    test_vrf_helper::<grumpkin::G1>();
}

fn test_vrf_helper<C>()
where
    C: CurveExt + CofactorGroup,
    C::Scalar: FromUniformBytes<64> + SerdeObject,
    C::AffineExt: SerdeObject,
{
    let mut rng = test_rng();
    let keypair = VRFKeypair::<C>::random(&mut rng);
    let message = "the message to prove";
    let proof = keypair.prove(message.as_bytes());
    assert!(proof.verify(&keypair.public_key, message.as_bytes()));

    let output = proof.proof_to_hash();
    println!("output {}: {:?}", output.len(), output);
}
