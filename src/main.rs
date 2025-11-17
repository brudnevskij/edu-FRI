use crate::fri::{FriProof, prove, verify};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_std::rand::SeedableRng;
use ark_std::rand::prelude::StdRng;
use std::time::Instant;

mod fri;
mod merkle;
mod transcript;

fn random_coeffs<F: PrimeField>(deg_plus_1: usize, seed: u64) -> Vec<F> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..deg_plus_1).map(|_| F::rand(&mut rng)).collect()
}

fn main() {
    let mut args = std::env::args().skip(1).collect::<Vec<_>>();
    let tamper = args.iter().any(|x| x == "--tamper");
    args.retain(|x| x != &"--tamper");

    let n: usize = args.get(0).and_then(|s| s.parse().ok()).unwrap_or(64);
    let degp1: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(21);

    let domain = GeneralEvaluationDomain::<Fr>::new(n)
        .expect(format!("Failed to construct domain for n={}", n).as_str());
    assert!(
        degp1 <= n,
        "degree+1 must be ≤ domain size (got deg+1={}, N={})",
        degp1,
        n
    );

    let coeffs = random_coeffs::<Fr>(degp1, 1337);
    let seed = b"fri-demo-seed";

    println!("FRI demo");
    println!("  domain size: {}", n);
    println!("  polynomial degree: {}", degp1 - 1);
    println!("  to-constant folding, num_queries = 1");
    println!();

    // --- PROVE ---
    let t0 = Instant::now();
    let proof: FriProof<Fr> =
        prove::<Fr>(&coeffs, domain, seed).expect("honest prover should succeed");
    let dt_prove = t0.elapsed();

    println!("Prover output:");
    println!("  rounds (roots): {}", proof.roots.len());
    for (i, r) in proof.roots.iter().enumerate() {
        // print first 8 bytes as hex for brevity
        let prefix = &r[..std::cmp::min(8, r.len())];
        let hex = prefix
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>();
        println!("    root[{i}]: {}…", hex);
    }
    println!("  final const: {:}", proof.final_eval.into_bigint());
    println!("  prove time: {:.3?}", dt_prove);
    println!();

    let mut proof_to_check = proof.clone();
    if tamper {
        if let Some(q) = proof_to_check.queries.get_mut(0) {
            if let Some(r0) = q.rounds.get_mut(0) {
                // flip a bit in the left value
                r0.left.value += Fr::from(1u64);
                println!("(tampered) flipped first query/round left value");
            }
        }
    }

    // --- VERIFY ---
    // re-create the initial domain (verify only needs the first one)
    let verify_domain = GeneralEvaluationDomain::<Fr>::new(n).unwrap();

    let t1 = Instant::now();
    match verify::<Fr>(&proof_to_check, verify_domain, seed) {
        Ok(()) => {
            let dt_verify = t1.elapsed();
            println!("Verifier: ✅ ACCEPT");
            println!("  verify time: {:.3?}", dt_verify);
        }
        Err(e) => {
            let dt_verify = t1.elapsed();
            println!("Verifier: ❌ REJECT ({e})");
            println!("  verify time: {:.3?}", dt_verify);
            std::process::exit(1);
        }
    }
}
