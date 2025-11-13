use crate::merkle::{AuthPath, Digest};
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::GeneralEvaluationDomain;

pub struct FriProof<F: Field> {
    // Merkle roots per FRI step
    pub roots: Vec<Digest>,
    // Queries for each step of FRI, one per index queried
    pub queries: Vec<FriQuery<F>>,
    // Protocol's result polynomial
    pub final_coeffs: Vec<F>,
}

/// FriQuery contains folds for each step of FRI
pub struct FriQuery<F: Field> {
    pub rounds: Vec<FriRound<F>>,
}

/// FriRound contains left and right addend of FRI folding scheme and their auth
/// f(x), f(-x)
pub struct FriRound<F: Field> {
    pub left: Opened<F>,
    pub right: Opened<F>,
}

/// Opened contains value and merkle tree auth path
pub struct Opened<F: Field> {
    pub value: F,
    pub path: AuthPath,
}

pub fn prove<F: PrimeField + FftField>(
    coeffs: &[F],
    domain: GeneralEvaluationDomain<F>,
    min_poly_size: usize,
    fs_seed: &[u8],
) -> FriProof<F> {
    todo!()
}

pub fn verify<F: PrimeField + FftField>(
    proof: &FriProof<F>,
    domain: GeneralEvaluationDomain<F>,
    min_poly_size: usize,
    fs_seed: &[u8],
) -> bool {
    todo!()
}
