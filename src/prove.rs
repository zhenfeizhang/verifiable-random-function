use halo2curves::ff::PrimeField;
use halo2curves::group::GroupEncoding;
use halo2curves::{ff::FromUniformBytes, CurveExt};
use sha2::{Digest, Sha512};

use crate::{VRFKeypair, VRFProof};

impl<C> VRFKeypair<C>
where
    C: CurveExt,
    C::Scalar: FromUniformBytes<64> + PrimeField<Repr = [u8; 32]>,
{
    /// Utility function to convert a "secret key" (32-byte seed || 32-byte PK)
    /// into the public point Y, the private scalar x, and truncated hash of the
    /// seed to be used later in nonce generation.
    #[allow(dead_code)]
    pub(crate) fn expand_keypair(&self) -> (C::Scalar, [u8; 32]) {
        // This algorithm differs from the standard as follows:
        // - the standard invokes a single hash and splits the output into x_scalar and h
        // - in order to preserve uniformity over various curves, our x_scalar requires 64 bytes; therefore we invoke the hash function twice
        let serialized_keypair = [
            self.public_key.to_bytes().as_ref(),
            self.private_key.to_bytes().as_ref(),
        ]
        .concat();

        // x = hash(key|0)
        let mut hasher = Sha512::new();
        hasher.update([serialized_keypair.clone(), vec![0]].concat());
        let tmp: [u8; 64] = hasher.finalize().into();
        let x_scalar = C::Scalar::from_uniform_bytes(&tmp);

        // h = hash(key|1)
        let mut hasher = Sha512::new();
        hasher.update([serialized_keypair, vec![1]].concat());
        let h: [u8; 64] = hasher.finalize().into();

        (x_scalar, h[0..32].try_into().unwrap())
    }

    /// Deterministically generate a (secret) nonce to be used in a proof.
    /// Specified in draft spec section 5.4.2.2.
    /// Note: In the spec, this subroutine computes truncated_hashed_sk_string
    /// Here we instead takes it as an argument, and we compute it in vrf_expand_sk
    pub(crate) fn nonce_gen(&self, generator_h: C::Affine) -> C::Scalar {
        let mut hasher = Sha512::new();
        hasher.update(self.private_key.to_bytes());
        hasher.update(generator_h.to_bytes());
        let nonce: [u8; 64] = hasher.finalize().into();
        C::Scalar::from_uniform_bytes(&nonce)
    }

    /// Construct a proof for a message alpha per draft spec section 5.1.
    /// Takes in a secret scalar x, a public point Y, and a secret string
    /// truncated_hashed_sk that is used in nonce generation.
    /// These are computed from the secret key using the expand_sk function.
    pub fn prove(&self, alpha: &[u8]) -> VRFProof<C> {
        // 1.  Use SK to derive the VRF secret scalar x and the VRF public key Y
        //     = x*B
        //     (this derivation depends on the ciphersuite, as per Section 5.5;
        //     these values can be cached, for example, after key generation,
        //     and need not be rederived each time)
        // 2.  H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
        //     (see Section 5.4.1)
        // 3.  h_string = point_to_string(H)
        // 4.  Gamma = x*H
        // 5.  k = ECVRF_nonce_generation(SK, h_string) (see Section 5.4.2)
        // 6.  c = ECVRF_challenge_generation(Y, H, Gamma, k*B, k*H) (see
        //     Section 5.4.3)
        // 7.  s = (k + c*x) mod q
        // 8.  pi_string = point_to_string(Gamma) || int_to_string(c, cLen) ||
        //     int_to_string(s, qLen)
        // 9.  Output pi_string

        // h = hash_to_curve( sk | alpha )
        let generator_h = {
            // this function differs from the standard in that we use halo2's
            // default hash-to-curve function, instead of the alligator hash
            let hasher = C::hash_to_curve("vrf hash");
            hasher(
                [self.public_key.to_bytes().as_ref(), alpha]
                    .concat()
                    .as_slice(),
            )
        };
        let generator_h_affine = generator_h.to_affine();
        dbg!("generator h in proving: {:?}", generator_h_affine);

        // gamma = x * h
        let gamma = generator_h * self.private_key.scalar_x;
        let gamma_affine = gamma.to_affine();
        dbg!("gamma in proving: {:?}", gamma_affine);
        // k = hash(sk | h)
        let nonce_k = self.nonce_gen(generator_h_affine);

        // k * generator_b
        let kb = C::generator() * nonce_k;
        dbg!("kb in proving: {:?}", kb.to_affine());

        // k * h
        let kh = generator_h * nonce_k;
        dbg!("kh in proving: {:?}", kh.to_affine());

        // challenge c = hash(h, gamma, kb, kh)
        let challenge_c = {
            let mut hasher = Sha512::new();
            hasher.update(generator_h_affine.to_bytes());
            hasher.update(gamma_affine.to_bytes());
            hasher.update(kb.to_affine().to_bytes());
            hasher.update(kh.to_affine().to_bytes());
            let tmp: [u8; 64] = hasher.finalize().into();
            // in the standard, challenge is a uniform 128 bits integer
            C::ScalarExt::from_u128(u128::from_le_bytes(tmp[0..16].try_into().unwrap()))
        };

        // s = c * x + k
        let scalar_s = challenge_c * self.private_key.scalar_x + nonce_k;

        VRFProof {
            challenge_c,
            scalar_s,
            point_gamma: gamma_affine,
        }
    }
}
