use crate::merkle::Digest;
use ark_ff::{Field, PrimeField};

pub struct Transcript {
    state: [u8; 32],
    counter: u64,
    label: Vec<u8>,
}

impl Transcript {
    pub fn new(label: &[u8], seed: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(b"transcript:init");
        h.update(label);
        h.update(seed);
        let state = *h.finalize().as_bytes();
        Self {
            state,
            counter: 0,
            label: label.to_vec(),
        }
    }

    pub fn absorb_bytes(&mut self, label: &str, data: &[u8]) {
        let mut h = blake3::Hasher::new();
        h.update(b"transcript:absorb");
        h.update(&self.state);
        h.update(&self.label);
        h.update(label.as_bytes());
        h.update(data);
        self.state = *h.finalize().as_bytes();
    }

    pub fn absorb_field<F: Field>(&mut self, label: &str, x: &F) {
        let mut buf = Vec::new();
        x.serialize_compressed(&mut buf).expect("serialize field");
        self.absorb_bytes(label, &buf);
    }

    pub fn absorb_digest(&mut self, d: &Digest) {
        self.absorb_bytes("digest", d);
    }

    /// Convenience: absorb common FRI params.
    pub fn absorb_params(&mut self, domain_size: usize, terminal_size: usize, num_queries: usize) {
        let mut v = Vec::with_capacity(24);
        v.extend_from_slice(&(domain_size as u64).to_le_bytes());
        v.extend_from_slice(&(terminal_size as u64).to_le_bytes());
        v.extend_from_slice(&(num_queries as u64).to_le_bytes());
        self.absorb_bytes("fri/params", &v);
    }

    /// Derive `n` pseudo-random bytes from the transcript (domain-separated by label + counter).
    pub fn challenge_bytes(&mut self, label: &str, n: usize) -> Vec<u8> {
        let mut base = blake3::Hasher::new();
        base.update(b"transcript:challenge");
        base.update(&self.state);
        base.update(&self.label);
        base.update(label.as_bytes());
        base.update(&self.counter.to_le_bytes());
        self.counter = self.counter.wrapping_add(1);

        // Use XOF to produce as many bytes as needed.
        let mut xof = base.finalize_xof();
        let mut out = vec![0u8; n];
        xof.fill(&mut out);
        out
    }

    pub fn challenge_u64(&mut self, label: &str) -> u64 {
        let b = self.challenge_bytes(label, 8);
        u64::from_le_bytes(b.try_into().expect("len 8"))
    }

    /// Derive a field element challenge via canonical mod-p reduction.
    pub fn challenge_field<F: PrimeField>(&mut self, label: &str) -> F {
        let bytes = self.challenge_bytes(label, 64);
        F::from_le_bytes_mod_order(&bytes)
    }

    /// Sample an unbiased index in [0, n) using rejection sampling.
    pub fn challenge_index(&mut self, label: &str, n: u64) -> u64 {
        assert!(n > 0, "n must be > 0");
        let limit = u64::MAX / n * n; // largest multiple of n ≤ u64::MAX
        loop {
            let x = self.challenge_u64(label);
            if x < limit {
                return x % n;
            }
        }
    }
}
