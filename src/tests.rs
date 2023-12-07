use ark_std::test_rng;
use halo2curves::group::GroupEncoding;
use halo2curves::{
    bn256,
    ff::{FromUniformBytes, PrimeField},
    group::cofactor::CofactorGroup,
    grumpkin, CurveExt,
};

use crate::{VRFKeypair, VRFPrikey, VRFProof, VRFPubkey};

#[test]
fn test_serialization() {
    test_serialization_helper::<bn256::G1>();
    test_serialization_helper::<grumpkin::G1>();
}

fn test_serialization_helper<C>()
where
    C: CurveExt,
    C::Scalar: FromUniformBytes<64> + PrimeField<Repr = [u8; 32]>,
{
    let mut rng = test_rng();
    let keypair = VRFKeypair::<C>::random(&mut rng);

    let sk_bytes = keypair.private_key.to_bytes();
    let pk_bytes = keypair.public_key.to_bytes();

    let sk_rec = VRFPrikey::<C>::from_bytes(&sk_bytes).unwrap();
    let pk_rec = VRFPubkey::<C>::from_bytes(&pk_bytes).unwrap();

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
    C::Scalar: FromUniformBytes<64> + PrimeField<Repr = [u8; 32]>,
{
    let mut rng = test_rng();
    let keypair = VRFKeypair::<C>::random(&mut rng);
    let message = "the message to prove";
    let proof = keypair.prove(message.as_bytes());
    let proof_bytes = proof.to_bytes();
    println!("proof {}: {:?}", proof_bytes.len(), proof_bytes);
    let proof_rec = VRFProof::<C>::from_bytes(&proof_bytes).unwrap();
    assert_eq!(proof, proof_rec);
    assert!(proof.verify(&keypair.public_key, message.as_bytes()));

    let output = proof.proof_to_hash();
    println!("output {}: {:?}", output.len(), output);
}
