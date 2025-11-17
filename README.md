# edu-FRI

A tiny, readable implementation of **FRI** (Fast Reed–Solomon IOP of Proximity) in Rust.  
**⚠️ Educational purposes only** - This is not a production library; it's a learning project with clear code paths you can step through.

What it does right now:

- Radix-2 subgroup domain (`ark-poly`’s `GeneralEvaluationDomain`)
- Prover commits to each FRI layer with a Merkle tree (BLAKE3)
- Fiat–Shamir transcript for non-interactive challenges
- Folds all the way down to a **constant** (no final interpolation)
- Verifier checks:
    - Merkle openings at each layer,
    - the **fold equation** per round,
    - and a **bridge check** that ties round *i* and *i+1*

---

## Quick start

```bash
# 1) build
cargo build

# 2) run a small demo (N=64, deg=20)
cargo run --release

# 3) try larger domain / different degree
cargo run --release -- 128 33

# 4) see a tampered-proof rejection
cargo run --release -- 64 21 --tamper

# 5) run tests
cargo test
```

You should see something like:

```
FRI demo
  domain size: 64
  polynomial degree: 20
  to-constant folding, num_queries = 1

Prover output:
  rounds (roots): 6
    root[0]: 118e487caab38274…
    root[1]: 5ece68f6fad9c43d…
    root[2]: 496a17527790eb33…
    root[3]: 93bda5e992f92066…
    root[4]: c3c25d8208a176c7…
    root[5]: 77775fe4071f7847…
  final const: 20806709307195930619058413498434228541072714638478897478489993841504654929636
  prove time: 1.381ms

Verifier: ✅ ACCEPT
  verify time: 697.216µs
```

Use `--tamper` to flip a value and watch the verifier reject.

---

## Code layout

```
src/
  main.rs         # small demo pipeline (prove → verify; optional tamper)
  fri.rs          # prover & verifier
  merkle.rs       # Merkle tree (blake3), leaf/node domain separation
  transcript.rs   # tiny Fiat–Shamir transcript (blake3-based)
```

The code tries to be boring and explicit. No macros, no magic.

---

## How it works (short version)
- Choose a power-of-two domain $D_0 = \{g^j\}$ and evaluate your polynomial on it.
- Commit the evaluations with a Merkle tree → $\text{root}_0$.
- Fiat–Shamir challenge $\beta_0$.
- **Fold** the vector pairwise:

  $$f^*(x^2) = \frac{f(x)+f(-x)}{2} + \beta_0 \cdot \frac{f(x)-f(-x)}{2x}$$

- Repeat: commit → challenge → fold. Each round halves length and squares the generator.
- Stop at length 1 (a constant). Bind that constant in the transcript.
- Verifier replays the same challenges, checks Merkle paths, checks the fold equation per round, and finally checks the constant. In addition, verifier checks that the folded value at layer $i+1$ matches the computed fold from layer $i$:
$$f_{D_{i+1}}(x^2) = \frac{f_{D_i}(x) + f_{D_i}(-x)}{2} + \beta_i \cdot \frac{f_{D_i}(x) - f_{D_i}(-x)}{2x}$$ 
---

## API sketch

```rust
// Prove: folds to constant and returns {roots, per-query openings, final_const}
pub fn prove<F: PrimeField + FftField>(
    coeffs: &[F],
    domain0: GeneralEvaluationDomain<F>,
    fs_seed: &[u8],
) -> Result<FriProof<F>, ProofError>;

// Verify: replays transcript, checks merkle proofs, folds, bridges, final const
pub fn verify<F: PrimeField + FftField>(
    proof: &FriProof<F>,
    domain0: GeneralEvaluationDomain<F>,
    fs_seed: &[u8],
) -> Result<(), VerificationError>;
```
## Possible improvements 

- [ ] Parameterize `num_queries`
- [ ] Terminal size (t = 32 or 64) and send `final_coeffs` or `final_evals`
- [ ] Batch merkle path verification across queries/rounds
- [ ] Optional coset offset
- [ ] Basic benches

---

## Materials used to learn / implement:
- [Anatomy of a STARK part 3](https://aszepieniec.github.io/stark-anatomy/fri.html) - clear intuition and structure.
- [A summary on the FRI low degree test](https://eprint.iacr.org/2022/1216.pdf?ref=blog.lambdaclass.com) - an informal summary paper on FRI.
- [Fast Reed-Solomon IOP (FRI) Proximity Test](https://rot256.dev/post/fri/) - a great blog post from an unusual angle, with algebra, examples and exercises.

---

## License

MIT. Do what you want; attribution appreciated.