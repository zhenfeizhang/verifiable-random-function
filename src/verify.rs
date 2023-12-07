use halo2curves::ff::PrimeField;
use halo2curves::group::prime::PrimeCurveAffine;
use halo2curves::group::GroupEncoding;
use halo2curves::{group::cofactor::CofactorGroup, CurveExt};
use sha2::{Digest, Sha512};

use crate::{VRFProof, VRFPubkey};

impl<C> VRFProof<C>
where
    C::Scalar: PrimeField<Repr = [u8; 32]>,
    C: CurveExt,
{
    /// Convert the proof to bytes.
    /// Use uncompressed form of the group elements
    pub fn to_bytes(&self) -> Vec<u8> {
        [
            self.challenge_c.to_repr()[..16].as_ref(),
            self.scalar_s.to_repr().as_ref(),
            self.point_gamma.to_bytes().as_ref(),
        ]
        .concat()
    }

    /// Convert bytes to a proof.
    /// Use uncompressed form of the group elements
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        assert_eq!(bytes.len(), 80, "incorrect proof size");

        let challenge_c =
            C::Scalar::from_u128(u128::from_le_bytes(bytes[..16].try_into().unwrap()));

        let scalar_s = match C::Scalar::from_repr(bytes[16..48].try_into().unwrap()).into() {
            Some(p) => p,
            None => return None,
        };

        let point_gamma: C = {
            let mut encoding = <C as GroupEncoding>::Repr::default();
            encoding.as_mut().copy_from_slice(bytes[48..].as_ref());
            match C::from_bytes(&encoding).into() {
                Some(p) => p,
                None => return None,
            }
        };

        Some(Self {
            challenge_c,
            scalar_s,
            point_gamma: point_gamma.to_affine(),
        })
    }
}

impl<C> VRFProof<C>
where
    C: CofactorGroup,
    C: CurveExt,
{
    /// Convert a VRF proof pi into a VRF output hash beta per draft spec section 5.2.
    /// This function does not verify the proof! For an untrusted proof, instead call
    /// crypto_vrf_ietfdraft03_verify, which will output the hash if verification
    /// succeeds.
    /// Returns error if failure decoding the proof.
    pub fn proof_to_hash(&self) -> Vec<u8> {
        // 1.  D = ECVRF_decode_proof(pi_string) (see Section 5.4.4)
        // 2.  If D is "INVALID", output "INVALID" and stop
        // 3.  (Gamma, c, s) = D
        // 4.  proof_to_hash_domain_separator_front = 0x03
        // 5.  proof_to_hash_domain_separator_back = 0x00
        // 6.  beta_string = Hash(suite_string ||
        //     proof_to_hash_domain_separator_front || point_to_string(cofactor
        //     * Gamma) || proof_to_hash_domain_separator_back)
        let suite_string = C::CURVE_ID.as_bytes();

        let gamma: C = self.point_gamma.to_curve().clear_cofactor().into();
        dbg!("gamma: {:?}", gamma);

        let mut hasher = Sha512::new();
        hasher.update(
            [
                suite_string,
                &[3],
                gamma.to_affine().to_bytes().as_ref(),
                &[0],
            ]
            .concat(),
        );

        hasher.finalize().to_vec()
    }

    /// Verify a proof per draft section 5.3. Return error on failure.
    /// We assume Y_point has passed public key validation already.
    pub fn verify(&self, public_key: &VRFPubkey<C>, alpha: &[u8]) -> bool {
        // 1.   Y = string_to_point(PK_string)
        // 2.   If Y is "INVALID", output "INVALID" and stop
        // 3.   If validate_key, run ECVRF_validate_key(Y) (Section 5.4.5); if
        //      it outputs "INVALID", output "INVALID" and stop
        // 4.   D = ECVRF_decode_proof(pi_string) (see Section 5.4.4)
        // 5.   If D is "INVALID", output "INVALID" and stop
        // 6.   (Gamma, c, s) = D
        // 7.   H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
        //      (see Section 5.4.1)
        // 8.   U = s*B - c*Y
        // 9.   V = s*H - c*Gamma
        // 10.  c' = ECVRF_challenge_generation(Y, H, Gamma, U, V) (see
        //      Section 5.4.3)
        // 11.  If c and c' are equal, output ("VALID",
        //      ECVRF_proof_to_hash(pi_string)); else output "INVALID"

        // h = hash_to_curve( sk | alpha )
        let generator_h = {
            // this function differs from the standard in that we use halo2's
            // default hash-to-curve function, instead of the alligator hash
            let hasher = C::hash_to_curve("vrf hash");
            hasher([public_key.to_bytes().as_ref(), alpha].concat().as_slice())
        };
        let generator_h_affine = generator_h.to_affine();
        dbg!("generator h in verification: {:?}", generator_h_affine);
        dbg!("gamma in verification: {:?}", self.point_gamma);
        // calculate U = s*B - c*Y
        let u = C::generator() * self.scalar_s - public_key.point_y * self.challenge_c;
        dbg!("u in verification: {:?}", u.to_affine());

        // calculate V = s*H - c*Gamma
        let v = generator_h * self.scalar_s - self.point_gamma * self.challenge_c;
        dbg!("v in verification: {:?}", v.to_affine());

        // challenge c' = hash(h, gamma, u, v)
        let challenge_c = {
            let mut hasher = Sha512::new();
            hasher.update(generator_h_affine.to_bytes());
            hasher.update(self.point_gamma.to_bytes());
            hasher.update(u.to_affine().to_bytes());
            hasher.update(v.to_affine().to_bytes());
            let tmp: [u8; 64] = hasher.finalize().into();
            // in the standard, challenge is a uniform 128 bits integer
            C::ScalarExt::from_u128(u128::from_le_bytes(tmp[0..16].try_into().unwrap()))
        };
        self.challenge_c == challenge_c
    }
}
