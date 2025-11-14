use crate::merkle::{AuthPath, Blake3Hasher, Digest, MerkleError, MerkleTree};
use crate::transcript::Transcript;
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

    // convert Vec<F> to slice of bytes
    let mut leaves_bytes: Vec<Vec<u8>> = Vec::with_capacity(evals.len());
    for x in &evals {
        let mut buf = Vec::new();
        x.serialize_compressed(&mut buf).expect("field serialize");
        leaves_bytes.push(buf);
    }
    let row_refs: Vec<&[u8]> = leaves_bytes.iter().map(|v| v.as_slice()).collect();

    let tree = MerkleTree::<Blake3Hasher>::from_rows(&row_refs)?;
    let root = tree.root();

    // getting random challenge
    let mut tx = Transcript::new(b"fri", fs_seed);
    tx.absorb_digest(root);
    let alpha = tx.challenge_field("alpha");

    let f_star_evals = fold_poly(&evals, domain, alpha);

    todo!()
}

fn fold_poly<F: PrimeField + FftField>(
    evals: &[F],
    domain: GeneralEvaluationDomain<F>,
    challenge: F,
) -> Vec<F> {
    let n = evals.len();
    assert!(n.is_power_of_two() && n >= 2);
    let half = n / 2;

    let inv2 = F::from(2u64).inverse().expect("inverse");
    let g = domain.group_gen();
    let mut x = domain.element(0);

    let mut out = Vec::with_capacity(half);
    for i in 0..half {
        let j = i + half;

        // f(x), f(-x)
        let fx = evals[i];
        let fnegx = evals[j];

        if i > 0 {
            x *= g;
        }

        // even/odd parts
        let f_even = (fx + fnegx) * inv2;
        // can be accumulated also
        let inv2x = inv2 * x.inverse().unwrap();
        let f_odd = (fx - fnegx) * inv2x;

        let f_star = f_even + challenge * f_odd;
        out.push(f_star);
    }

    out
}

pub fn verify<F: PrimeField + FftField>(
    proof: &FriProof<F>,
    domain: GeneralEvaluationDomain<F>,
    min_poly_size: usize,
    fs_seed: &[u8],
) -> bool {
    todo!()
}
