//! Some simple structs for defining window sizes and number of windows for commitment schemes and
//! Merkle tree hashes.

use ark_crypto_primitives::commitment::pedersen::Window;

/// Window sizes and number of windows for the client's commitment scheme.
/// Window size is 4 (optimal for `BasicConfig`). Number of windows is chosen optimally based on the
/// number of bytes we commit to.
#[derive(Clone)]
pub struct ClientCommitmentSchemeWindow<const NUM_BYTES: usize>;

impl<const NUM_BYTES: usize> Window for ClientCommitmentSchemeWindow<NUM_BYTES> {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 2 * NUM_BYTES;
}

/// Window sizes and number of windows for a Merkle Tree using Pedersen hashes.
/// Window size is 4 (optimal for the Pedersen Hash). Number of windows is set to 256 accordingly.
#[derive(Clone)]
pub struct PedersenMerkleTreeWindow;

impl Window for PedersenMerkleTreeWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}
