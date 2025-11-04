
pub type Digest = [u8; 32];

pub struct AuthPath {
    pub nodes: Vec<Digest>,
    pub index: usize,
}

pub trait Hasher {
    fn hash_leaf(&self, data: &[u8]) -> Digest;
    fn hash_node(&self, left_node: &Digest, right_node: &Digest) -> Digest;
}

pub struct Blake3Hasher;
impl Hasher for Blake3Hasher {
    fn hash_leaf(&self, data: &[u8]) -> Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[0x00]);
        hasher.update(data);
        *hasher.finalize().as_bytes()
    }

    fn hash_node(&self, left: &Digest, right: &Digest) -> Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[0x01]);
        hasher.update(left);
        hasher.update(right);
        *hasher.finalize().as_bytes()
    }
}

pub struct MerkleTree<H: Hasher = Blake3Hasher> {
    nodes: Vec<Digest>,
    leaf_count: usize,
    _h: core::marker::PhantomData<H>,
}