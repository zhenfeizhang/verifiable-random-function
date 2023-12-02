use halo2curves::{group::Curve, CurveExt};

mod keys;
mod prove;
mod verify;

#[derive(Debug, Clone, Copy, Default)]
pub struct VRFKeypair<C: Curve> {
    pub public_key: VRFPubkey<C>,
    pub private_key: VRFPrikey<C>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VRFPubkey<C: Curve> {
    pub point_y: C,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VRFPrikey<C: Curve> {
    pub scalar_x: C::Scalar,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct VRFProof<C: CurveExt> {
    pub challenge_c: C::Scalar,
    pub scalar_s: C::Scalar,
    pub point_gamma: C::Affine,
}
#[cfg(test)]
mod tests;
