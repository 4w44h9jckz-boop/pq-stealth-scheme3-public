//! Per-announcement scan cost and its parts, for `tools/scan_projection.py`.
//!
//! `cargo run --release -p pqsa-per-payment --example scan_timing -- <ikm bytes>...`
//!
//! Prints one JSON object of mean microseconds: the whole `SchemeId3::scan` for an
//! announcement addressed to someone else (what nearly every announcement is) and for one's
//! own, then its parts: the ECDH, ML-KEM-768 decapsulation from the 64-byte seed as the
//! scanner does it, the seed expansion alone, the view-tag digest, and SHA3-256 over each
//! combiner-input length given on the command line.
use std::hint::black_box;
use std::time::{Duration, Instant};

use pqsa_core::StealthScheme;
use pqsa_kem::{Kem, MlKem768};
use pqsa_per_payment::SchemeId3;
use serde_json::{Map, Value, json};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

const BATCH: Duration = Duration::from_millis(300);
const BATCHES: usize = 7;

/// Median over `BATCHES` of the mean time per call in a batch of about `BATCH`, in µs.
fn time(mut f: impl FnMut()) -> f64 {
    for _ in 0..20 {
        f();
    }
    let mut means: Vec<f64> = (0..BATCHES)
        .map(|_| {
            let (mut calls, start) = (0u32, Instant::now());
            while start.elapsed() < BATCH {
                f();
                calls += 1;
            }
            start.elapsed().as_secs_f64() * 1e6 / f64::from(calls)
        })
        .collect();
    means.sort_by(f64::total_cmp);
    means[BATCHES / 2]
}

fn seed(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(salt))
        .collect()
}

fn main() {
    let ikm_lengths: Vec<usize> = std::env::args()
        .skip(1)
        .map(|a| a.parse().expect("combiner-input lengths in bytes"))
        .collect();

    let (meta, _, tracking) = SchemeId3::keygen(&seed(128, 3)).expect("keygen");
    let (other_meta, _, _) = SchemeId3::keygen(&seed(128, 101)).expect("keygen");
    let scanner = SchemeId3::bind(&tracking, &meta).expect("bind");
    let own = SchemeId3::announce(&meta, &seed(64, 7)).expect("announce");
    let foreign = SchemeId3::announce(&other_meta, &seed(64, 9)).expect("announce");
    assert!(SchemeId3::scan(&scanner, &own).is_some());
    assert!(SchemeId3::scan(&scanner, &foreign).is_none());

    let viewing_scalar = [0x11u8; 32];
    let point = pqsa_ec::public_point(&[0x22u8; 32]).expect("point");
    let kem_seed = seed(MlKem768::KEYGEN_SEED_BYTES, 5);
    let (ek, _) = MlKem768::keygen(&kem_seed).expect("keygen");
    let (ct, _) = MlKem768::encapsulate(&ek, &seed(32, 13)).expect("encapsulate");

    let mut sha3 = Map::new();
    for len in ikm_lengths {
        let input = seed(len, 17);
        let us = time(|| {
            black_box(Sha3_256::digest(black_box(&input)));
        });
        sha3.insert(len.to_string(), json!(us));
    }
    let tag_input = seed(22 + 32, 19);

    let out = json!({
        "scan_foreign_us": time(|| { black_box(SchemeId3::scan(&scanner, black_box(&foreign))); }),
        "scan_own_us": time(|| { black_box(SchemeId3::scan(&scanner, black_box(&own))); }),
        "ecdh_us": time(|| { black_box(pqsa_ec::ecdh(&viewing_scalar, black_box(&point)).ok()); }),
        "mlkem768_decapsulate_from_seed_us":
            time(|| { black_box(MlKem768::decapsulate(&kem_seed, black_box(&ct)).ok()); }),
        "mlkem768_expand_seed_us":
            time(|| { black_box(MlKem768::keygen(black_box(&kem_seed)).ok()); }),
        "view_tag_sha256_us": time(|| { black_box(Sha256::digest(black_box(&tag_input))); }),
        "sha3_256_us_by_length": Value::Object(sha3),
    });
    println!("{out}");
}
