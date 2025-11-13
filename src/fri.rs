use crate::merkle::{AuthPath, Digest, MerkleError, MerkleTree};
use ark_ff::{FftField, Field, PrimeField};
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use thiserror::Error;

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

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("polynomial degree is bigger then domain")]
    DegreeExceedsDomain,
    #[error("minimal polynomial size is invalid")]
    InvalidTerminalSize,

    #[error(transparent)]
    Merkle(#[from] MerkleError),
}

pub fn prove<F: PrimeField + FftField>(
    coeffs: &[F],
    domain: GeneralEvaluationDomain<F>,
    min_poly_size: usize,
    fs_seed: &[u8],
) -> Result<FriProof<F>, ProofError> {
    let domain_size = domain.size();
    let degree = coeffs.len() - 1;

    // degree must fit the domain
    if coeffs.is_empty() || degree > domain_size - 1 {
        return Err(ProofError::DegreeExceedsDomain);
    }

    if min_poly_size == 0 || min_poly_size > domain_size || !min_poly_size.is_power_of_two() {
        return Err(ProofError::InvalidTerminalSize);
    }

    let mut evals = vec![F::zero(); degree];
    evals[..coeffs.len()].copy_from_slice(&coeffs);
    domain.fft_in_place(&mut evals);

    let evals_tree = MerkleTree::from_rows(&evals)?;
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
