use std::marker::PhantomData;
use thiserror::Error;

pub type Digest = [u8; 32];

pub struct AuthPath {
    pub nodes: Vec<Digest>,
    pub index: usize,
}

#[derive(Error, Debug)]
pub enum MerkleError {
    #[error("empty input")]
    Empty,
    #[error("index out of range")]
    IndexOutOfRange,
}

pub trait Hasher {
    fn hash_leaf(data: &[u8]) -> Digest;
    fn hash_node(left_node: &Digest, right_node: &Digest) -> Digest;
}

pub struct Blake3Hasher;
impl Hasher for Blake3Hasher {
    fn hash_leaf(data: &[u8]) -> Digest {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[0x00]);
        hasher.update(data);
        *hasher.finalize().as_bytes()
    }

    fn hash_node(left: &Digest, right: &Digest) -> Digest {
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
    leaf_cap: usize,
    _h: PhantomData<H>,
}

impl<H: Hasher> MerkleTree<H> {
    pub fn from_rows(rows: &[&[u8]]) -> Result<Self, MerkleError> {
        if rows.is_empty() {
            return Err(MerkleError::Empty);
        }
        let leaves: Vec<Digest>= rows.iter().map(|x| H::hash_leaf(x)).collect();
        Ok(Self::from_leaf_digests(&leaves)?)
    }

    pub fn from_leaf_digests(leaves: &[Digest]) -> Result<Self, MerkleError> {
        if leaves.is_empty() {
            return Err(MerkleError::Empty);
        }
        let leaf_count = leaves.len();
        let cap = next_pow2(leaf_count);

        // since number of leaves is power of 2, cap also includes, next floors which are also powers of two
        // making the sum = 2^leaf_count + (2^leaf_count - 1) + 1 (last is unused 0th index) = 2 * 2^leaf_count
        let mut nodes = vec![[0u8; 32]; cap * 2];

        for (i, leaf) in leaves.iter().enumerate() {
            nodes[cap + i] = *leaf;
        }

        for i in leaf_count..cap {
            nodes[cap + i] = nodes[cap + leaf_count - 1];
        }

        for i in (1..cap).rev() {
            let l = nodes[2 * i];
            let r = nodes[2 * i + 1];
            nodes[i] = H::hash_node(&l, &r);
        }

        Ok(Self {
            nodes,
            leaf_count,
            leaf_cap: cap,
            _h: PhantomData,
        })
    }

    pub fn root(&self) -> &Digest {
        &self.nodes[1]
    }
}

fn next_pow2(n: usize) -> usize {
    // treat n >= 1
    let mut x = n - 1;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    if usize::BITS > 32 {
        x |= x >> 32;
    }
    x + 1
}
