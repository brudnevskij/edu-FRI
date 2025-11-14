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


#[derive(Debug)]
struct RoundDomain<F> {
    generator: F,
    size: usize,
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

    /// committing to f(x)
    let mut evals = vec![F::zero(); domain_size];
    evals[..coeffs.len()].copy_from_slice(&coeffs);
    domain.fft_in_place(&mut evals);
    let leaf_vecs = evals_to_bytes(&evals);
    let leaf_slices: Vec<&[u8]> = leaf_vecs.iter().map(|v| v.as_slice()).collect();

    let tree = MerkleTree::<Blake3Hasher>::from_rows(&leaf_slices)?;
    let root = tree.root();

    // getting random challenge
    let mut tx = Transcript::new(b"fri", fs_seed);
    tx.absorb_digest(root);
    let alpha = tx.challenge_field("alpha");

    /// calculating f*(x) codeword and committing to it
    let f_star_evals = fold_once(&evals, domain.group_gen(), alpha);
    let f_star_leafs = evals_to_bytes(&f_star_evals);
    let f_star_leafs = f_star_leafs.iter().map(|v| v.as_slice()).collect::<Vec<_>>();

    let f_star_tree = MerkleTree::<Blake3Hasher>::from_rows(&f_star_leafs)?;
    let f_star_root = f_star_tree.root();

    tx.absorb_digest(f_star_root);
    // sampling i in [0..n/2)
    let i = tx.challenge_index("i_query", f_star_evals.len() as u64);


    todo!()
}

// convert Vec<F> to slice of bytes
fn evals_to_bytes<F: PrimeField + FftField>(evals: &[F]) -> Vec<Vec<u8>> {
    let mut leaves_bytes: Vec<Vec<u8>> = Vec::with_capacity(evals.len());
    for x in evals {
        let mut buf = Vec::new();
        x.serialize_compressed(&mut buf).expect("field serialize");
        leaves_bytes.push(buf);
    }
    leaves_bytes
}

fn fold_once<F: PrimeField + FftField>(evals: &[F], g: F, beta: F)-> Vec<F>{
    let n = evals.len();
    let half = n / 2;

    let inv2 = F::from(2u64).inverse().expect("inverse");
    let ginv = g.inverse().expect("inverse");

    let mut invx = F::one();
    let mut out = Vec::with_capacity(half);
    for i in 0..half {
        let j = i + half;
        let fx = evals[i];
        let fnegx = evals[j];

        let f_even = (fx + fnegx) * inv2;
        let f_odd = (fx - fnegx) * inv2 * invx;

        out.push(f_even + beta * f_odd);

        invx = invx * ginv
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

#[cfg(test)]
mod tests {
    use super::{fold_once};
    use ark_bn254::Fr;
    use ark_ff::{Field, UniformRand, Zero};
    use ark_poly::univariate::DensePolynomial;
    use ark_poly::{DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain};
    use ark_std::rand::{SeedableRng, rngs::StdRng};

    // build f(x) from random coeffs of given length
    fn random_poly(deg_plus_1: usize, seed: u64) -> DensePolynomial<Fr> {
        let mut rng = ark_std::test_rng();
        let coeffs: Vec<Fr> = (0..deg_plus_1).map(|_| Fr::rand(&mut rng)).collect();
        DensePolynomial::from_coefficients_slice(&coeffs)
    }

    // split f(X) = g(X^2) + X h(X^2) ⇒ return (g(Y), h(Y)) as polynomials in Y
    fn even_odd_split(f: &DensePolynomial<Fr>) -> (DensePolynomial<Fr>, DensePolynomial<Fr>) {
        let coeffs = &f.coeffs;
        let mut g = Vec::new(); // even coeffs a_0, a_2, a_4 -> g_0, g_1, g_2
        let mut h = Vec::new(); // odd  coeffs a_1, a_3, a_5 -> h_0, h_1, h_2
        for (k, a) in coeffs.iter().cloned().enumerate() {
            if k % 2 == 0 {
                g.push(a);
            } else {
                h.push(a);
            }
        }
        (
            DensePolynomial::from_coefficients_vec(g),
            DensePolynomial::from_coefficients_vec(h),
        )
    }

    // evaluate polynomial p at point x using Horner
    fn eval_poly(p: &DensePolynomial<Fr>, x: Fr) -> Fr {
        p.coeffs
            .iter()
            .rev()
            .fold(Fr::zero(), |acc, &c| acc * x + c)
    }

    #[test]
    fn fold_matches_even_odd_combo_small() {
        let n = 16usize;
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();

        let f = random_poly(10, 1337);
        // compute evals on D0 directly (not FFT), to be agnostic
        let g = domain.group_gen();
        let mut x = domain.element(0);
        let mut evals = Vec::with_capacity(n);
        for i in 0..n {
            if i > 0 {
                x *= g;
            }
            evals.push(eval_poly(&f, x));
        }

        // random beta
        let mut rng = StdRng::seed_from_u64(42);
        let beta = Fr::rand(&mut rng);

        let folded = fold_once(&evals, g, beta);

        // expected: u(Y) = g(Y) + beta * h(Y), evaluated at Y = x_j^2
        let (g_poly, h_poly) = even_odd_split(&f);
        let u_poly = DensePolynomial::from_coefficients_vec({
            // u = g + beta*h
            let (mut u, m) = (g_poly.clone(), h_poly.clone());
            let mut coeffs = u.coeffs;
            if coeffs.len() < m.coeffs.len() {
                coeffs.resize(m.coeffs.len(), Fr::zero());
            }
            for (k, c) in m.coeffs.iter().enumerate() {
                coeffs[k] += *c * beta;
            }
            coeffs
        });

        let half = n / 2;
        let mut xj = domain.element(0);
        let mut expected = Vec::with_capacity(half);
        for j in 0..half {
            if j > 0 {
                xj *= g;
            }
            let y = xj.square();
            expected.push(eval_poly(&u_poly, y));
        }

        assert_eq!(folded.len(), half);
        assert_eq!(expected.len(), half);
        for (a, b) in folded.iter().zip(expected.iter()) {
            assert_eq!(a, b, "mismatch at some index");
        }
    }

    #[test]
    fn fold_beta_zero_is_even_average() {
        let n = 8usize;
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();

        // build any polynomial and eval on grid
        let f = random_poly(6, 7);
        let g = domain.group_gen();
        let mut x = domain.element(0);
        let mut evals = Vec::with_capacity(n);
        for i in 0..n {
            if i > 0 {
                x *= g;
            }
            evals.push(eval_poly(&f, x));
        }

        // beta = 0 ⇒ f* = (f(x)+f(-x))/2
        let beta = Fr::zero();
        let folded = fold_once(&evals, g, beta);

        let inv2 = Fr::from(2u64).inverse().unwrap();
        let mut expected = Vec::with_capacity(n / 2);
        for i in 0..(n / 2) {
            expected.push((evals[i] + evals[i + n / 2]) * inv2);
        }

        assert_eq!(folded, expected);
    }

    #[test]
    fn pairing_invariant_minus_x_is_shift_by_half() {
        let n = 32usize;
        let domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();
        let g = domain.group_gen();
        let mut x = domain.element(0);

        // check that x_{i + n/2} = -x_i
        let half = n / 2;
        let mut xs: Vec<Fr> = Vec::with_capacity(n);
        for i in 0..n {
            if i > 0 {
                x *= g;
            }
            xs.push(x);
        }
        for i in 0..half {
            assert_eq!(xs[i + half], -xs[i]);
        }
    }
}
