use ark_std::test_rng;
use halo2curves::{
    bn256,
    ff::{FromUniformBytes, PrimeField},
    group::cofactor::CofactorGroup,
    grumpkin,
    serde::SerdeObject,
    CurveExt,
};

use crate::{VRFKeypair, VRFPrikey, VRFProof, VRFPubkey};

#[test]
fn test_serialization() {
    test_serialization_helper::<bn256::G1>();
    test_serialization_helper::<grumpkin::G1>();
}

fn test_serialization_helper<C>()
where
    C::Scalar: FromUniformBytes<64> + SerdeObject,
    C: CurveExt,
    C::Affine: SerdeObject,
{
    let mut rng = test_rng();
    let keypair = VRFKeypair::<C>::random(&mut rng);
    let keypair_bytes = keypair.to_raw_bytes();
    let sk_bytes = keypair.private_key.to_raw_bytes();
    let pk_bytes = keypair.public_key.to_raw_bytes();

    let keypair_rec = VRFKeypair::<C>::from_raw_bytes(&keypair_bytes).unwrap();
    let sk_rec = VRFPrikey::<C>::from_raw_bytes(&sk_bytes).unwrap();
    let pk_rec = VRFPubkey::<C>::from_raw_bytes(&pk_bytes).unwrap();
    assert_eq!(keypair, keypair_rec);
    assert_eq!(keypair.private_key, sk_rec);
    assert_eq!(keypair.public_key, pk_rec);
}

#[test]
fn test_vrf() {
    test_vrf_helper::<bn256::G1>();
    test_vrf_helper::<grumpkin::G1>();
}

fn test_vrf_helper<C>()
where
    C: CurveExt + CofactorGroup,
    C::Scalar: FromUniformBytes<64> + SerdeObject + PrimeField<Repr = [u8; 32]>,
    C::AffineExt: SerdeObject,
{
    let mut rng = test_rng();
    let keypair = VRFKeypair::<C>::random(&mut rng);
    let message = "the message to prove";
    let proof = keypair.prove(message.as_bytes());
    let proof_bytes = proof.to_raw_bytes();
    println!("proof: {:?}", proof);
    println!("proof_bytes: {:02x?}", proof_bytes[0..16].as_ref());
    let proof_rec = VRFProof::<C>::from_raw_bytes(&proof_bytes).unwrap();
    assert_eq!(proof, proof_rec);
    assert!(proof.verify(&keypair.public_key, message.as_bytes()));

    let output = proof.proof_to_hash();
    println!("output {}: {:?}", output.len(), output);
}
