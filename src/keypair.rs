use halo2curves::ff::FromUniformBytes;
use halo2curves::ff::PrimeField;
use halo2curves::group::GroupEncoding;
use halo2curves::CurveExt;
use rand_core::RngCore;
use sha2::Digest;
use sha2::Sha512;
use subtle::CtOption;

use crate::VRFKeypair;
use crate::VRFPrikey;
use crate::VRFPubkey;

impl<C> VRFKeypair<C>
where
    C::Scalar: FromUniformBytes<64>,
    C: CurveExt,
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
}

impl<C: CurveExt> From<VRFPrikey<C>> for VRFPubkey<C> {
    fn from(sk: VRFPrikey<C>) -> Self {
        let mut pk = C::generator();
        pk *= sk.scalar_x;
        VRFPubkey { point_y: pk }
    }
}

impl<C: CurveExt> VRFPrikey<C>
where
    C::Scalar: PrimeField<Repr = [u8; 32]>,
{
    /// Convert the private key to bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.scalar_x.to_repr()
    }

    /// Convert bytes to a private key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        C::Scalar::from_repr(*bytes)
            .map(|p| Self { scalar_x: p })
            .into()
    }
}

impl<C> GroupEncoding for VRFPubkey<C>
where
    C: CurveExt + GroupEncoding,
{
    type Repr = C::Repr;

    fn from_bytes(repr: &<Self as GroupEncoding>::Repr) -> CtOption<Self> {
        C::from_bytes(repr).map(|p| Self { point_y: p })
    }

    fn from_bytes_unchecked(repr: &<Self as GroupEncoding>::Repr) -> CtOption<Self> {
        C::from_bytes_unchecked(repr).map(|p| Self { point_y: p })
    }

    fn to_bytes(&self) -> <Self as GroupEncoding>::Repr {
        self.point_y.to_bytes()
    }
}
