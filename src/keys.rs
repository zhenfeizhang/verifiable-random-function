use halo2curves::ff::FromUniformBytes;
use halo2curves::group::Curve;
use halo2curves::serde::SerdeObject;
use rand_core::RngCore;
use sha2::Digest;
use sha2::Sha512;

use crate::VRFKeypair;
use crate::VRFPrikey;
use crate::VRFPubkey;

impl<C> VRFKeypair<C>
where
    C::Scalar: FromUniformBytes<64> + SerdeObject,
    C::AffineRepr: SerdeObject,
    C: Curve,
{
    /// Build a new pair of VRF keys
    pub fn new(seed: [u8; 32]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        let output: [u8; 64] = hasher.finalize().into();
        // map the output to the secret key is different from RFC 9381
        // we need 64 bytes to ensure uniformity over all curves
        let sk = C::Scalar::from_uniform_bytes(&output);
        let sk = VRFPrikey { scalar_x: sk };
        let pk = sk.into();

        VRFKeypair {
            public_key: pk,
            private_key: sk,
        }
    }

    /// Build a new pair of VRF keys from rng
    pub fn random(mut rng: impl RngCore) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::new(seed)
    }

    /// Convert the key pair to bytes.
    /// Use uncompressed form of the group elements
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        [
            self.private_key.to_raw_bytes(),
            self.public_key.to_raw_bytes(),
        ]
        .concat()
    }
}

impl<C: Curve> From<VRFPrikey<C>> for VRFPubkey<C> {
    fn from(sk: VRFPrikey<C>) -> Self {
        let mut pk = C::generator();
        pk *= sk.scalar_x;
        VRFPubkey { point_y: pk }
    }
}

impl<C: Curve> VRFPrikey<C>
where
    C::Scalar: SerdeObject,
{
    /// Convert the private key to bytes.
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        self.scalar_x.to_raw_bytes()
    }
}

impl<C> VRFPubkey<C>
where
    C: Curve,
    C::AffineRepr: SerdeObject,
{
    /// Convert the pub key to bytes.
    pub fn to_raw_bytes(&self) -> Vec<u8> {
        self.point_y.to_affine().to_raw_bytes()
    }
}
