# Scheme 3 — Lean 4 specification

A formal model of the protocol in
[`spec/ERC-VVVV-schemeid3.md`](../spec/ERC-VVVV-schemeid3.md)
and its Rust reference implementation, pinned to upstream commit
[`5fe8d0fd928155a56c74810ad9026807e548818b`](https://github.com/4w44h9jckz-boop/pq-stealth-scheme3-public/commit/5fe8d0fd928155a56c74810ad9026807e548818b).

This is an executable protocol model parameterized by cryptographic primitives,
with Lean proof scripts for its functional properties. It is not a verification
of the Rust implementation or a proof of post-quantum security.

## Build

Pinned toolchain: **Lean 4.19.0**. Only the toolchain's `Std` library is required;
there is no Mathlib or external Lean package dependency.

```sh
cd formal
lake build
lake env lean Audit.lean
```

The GitHub workflow performs both commands and rejects `sorryAx` in the audit.
The local authoring environment has no Lean compiler; the workflow result is the
source of truth for compilation status. Do not treat a pending build as verified.

## Model boundary

| File | Responsibility |
| --- | --- |
| [Scheme3/Base.lean](Scheme3/Base.lean) | Sized byte strings, big-endian scalar decoding, modular addition, hashes' exact input construction, offset search, primitive interfaces and EC proof obligations |
| [Scheme3/Protocol.lean](Scheme3/Protocol.lean) | Raw seed parsing, keygen, delegation guard, meta-address decoding, scanner binding, sender, event codec, scanning, spending and wallet obligations |
| [Scheme3/Proofs.lean](Scheme3/Proofs.lean) | Functional correctness and rejection proofs |
| [Audit.lean](Audit.lean) | Logical dependency reports for representative theorems |

`Primitives Point` exposes SHA-256, SHA3-256, Keccak-256, secp256k1 and ML-KEM
through typed operations. Every hash returns 32 bytes; KEM keys and ciphertexts
have fixed lengths. The concrete backend must implement these operations using
the specified algorithms. Arbitrary functions of the right types do not become
cryptographically secure.

`EcLaws p` is a theorem parameter containing four backend obligations:

1. Encoding then decoding a point returns that point.
2. Encoded points have compressed SEC1 prefix `0x02` or `0x03`.
3. ECDH x-coordinates agree when the two honest scalar inputs are exchanged.
4. Adding `offset*G` to `spending*G` agrees with modular scalar addition,
   including rejection at zero / the point at infinity.

There are **no declared project axioms**. These laws must be discharged for a
concrete secp256k1 backend before claiming an instantiated proof.

`KemAgrees p seed ct pq` is an explicit **per-instance hypothesis**
`Decaps(seed, ct) = pq`. The model does not install a universal
perfect-correctness axiom for ML-KEM. Its decryption failure probability and any
probabilistic correctness theorem belong to a subsequent primitive formalization.

## Wire and derivation contract

All concatenations below are exact and unprefixed unless stated.

| Item | Ordered bytes | Length |
| --- | --- | ---: |
| Keygen seed | spending scalar seed (32), viewing scalar seed (32), KEM `d || z` (64) | 128 |
| Delegated material | viewing scalar seed (32), KEM `d || z` (64) | 96 |
| Meta-address | compressed spending point (33), compressed viewing point (33), ML-KEM-768 ek (1184) | 1250 |
| Announce seed | ephemeral scalar seed (32), deterministic encapsulation message m (32) | 64 |
| `ephemeralPubKey` | compressed ephemeral point | 33 |
| `metadata` | one-byte view tag, ML-KEM-768 ciphertext | 1089 |
| Announcement payload counted by the repository | `ephemeralPubKey`, `metadata` | 1122 |

The 1122-byte count excludes the separate 20-byte announced address and ABI
overhead. The Ethereum address is represented by a fixed-width type, so the
all-zero address remains representable.

```text
ss_ec = x(ECDH(esk, viewing_pk_ec)), 32 bytes, big-endian
(ct, ss_pq) = ML-KEM-768.Encaps_internal(ek, m)
ss = SHA3-256(
  "pq-stealth/hybrid-payment/v1" ||
  ss_ec || ss_pq || compressed(epk) || ct || compressed(viewing_pk_ec) || ek
)
tag = SHA256("pq-stealth/view-tag/v1" || ss)[0]
base = SHA256("pq-stealth/offset/v1" || ss)
candidate(0) = base
candidate(c) = SHA256("pq-stealth/offset/v1" || base || byte(c mod 256))
offset = first candidate with 0 < u256be(candidate) < n, c in [0,256]
stealth_pk = spending_pk + offset*G
stealth_sk = (spending_sk + offset) mod n
address = Keccak-256(uncompressed_x || uncompressed_y)[12:32]
```

No valid offset after 257 candidates is a failure. Zero scalar sums and infinity
point sums also fail. A sender returns an error; a scanner turns these failures
into a skip.

The receiver obtains its shared secret by ECDH plus total decapsulation, then
checks the view tag, derives the stealth point and checks the announced address.
An accepted tag alone is insufficient. There is no view-tag prefilter before
ECDH and decapsulation.

## Main proof contracts

| Theorem | What it establishes | Dependencies beyond Lean |
| --- | --- | --- |
| `reduction_bounded` | A returned scalar came from a candidate with counter < 257 | None; hashes can be arbitrary |
| `last_candidate` | Counter 256 uses one byte `0x00` | None |
| `all_rejected_exhausts` | A candidate list with no valid scalar returns none | None |
| `delegation_covers_boundary` | Every offset 0–64 in the concatenated delegated object is covered | Accepted guard |
| `keygen_rejects_delegation` | Failed coincidence guard is an error | None |
| `keygen_length_rejected`, `announce_length_rejected` | Incorrect raw seed lengths are rejected | None |
| `meta_wire_length`, `metadata_wire_length`, `announcement_wire_length` | Exact 1250 / 1089 / 1122 byte counts | Typed primitive outputs |
| `metadata_tag_first` | Tag is the first metadata byte | None |
| `parse_announcement_roundtrip` | Serializing a typed announcement then parsing returns it | EC codec laws |
| `bind_generated` | Matching generated viewing and KEM material binds | None |
| `bind_accepts_same_ek` | A replacement KEM seed with the same ek also binds | Equality of ek outputs |
| `scan_accepts_iff` | Scan succeeds exactly when tag, offset, point and address checks pass | None |
| `scan_sound` | A returned match carries the announced address and recomputed secret | None |
| `tag_mismatch_skips`, `address_mismatch_skips` | Failed checks yield a skip | None |
| `foreign_scheme_skips`, `unregistered_scheme_skips` | Dispatcher enforces scheme 3 and recipient registration | None |
| `receiver_agreement` | Honest sender and receiver combine the same secret | ECDH symmetry, per-instance KEM agreement |
| `honest_payment` | Successful sender core announcement scans and yields the correct spending scalar | EC laws, encapsulation success, KEM agreement, offset success, nonzero scalar sum |
| `master_recovery` | One-time scalar plus offset algebraically recovers master scalar | Concrete modular arithmetic |
| `fresh_extension` | Extending a fresh seed history requires a new seed | None |
| `drawIndex_advances`, `drawIndex_exhausted` | Successful draws advance without wrapping; max counter rejects | None |

`scan_accepts_iff` is functional acceptance, **not cryptographic authenticity**.
It does not establish that a ciphertext came from an honest sender, that an event
was funded, or that a foreign announcement can never collide with the derived
tag and address. A correctly sized modified ciphertext still decapsulates to a
secret. If the tag and address for that secret agree, the scanner accepts it.

## Decisions and source differences

1. **Counter 256.** The prose uses `u8(counter)` up to 256 without specifying
   truncation explicitly. Rust's `reduce_to_scalar` casts the `u16` counter to
   `u8`, so the final retry hashes `DS || base || 0x00`. This model follows
   that implementation. It specifies 257 attempts, not 257 distinct digest
   values: hash collisions are possible.

2. **Binding the KEM seed.** Rust's test
   `z_is_not_publicly_bindable_but_is_used_for_implicit_rejection` records that
   changing `z` leaves ek unchanged and can still bind. `bind_accepts_same_ek`
   captures the public-binding limit without claiming to authenticate all
   64 secret bytes. The formal primitive interface does not itself implement
   the ML-KEM fact that ek is independent of z.

3. **Typed representation.** The Rust types have vestigial optional viewing
   fields and variable-length buffers. The Lean core has mandatory viewing
   fields and fixed-width KEM material. Raw codecs model malformed wire/seed
   inputs. Arbitrarily corrupted in-memory Rust structs, panic behavior and
   Rust error precedence outside those codecs are not modeled.

4. **Master object.** The Lean `Master` stores the spending scalar only, matching
   the normative disposition and what `spend_key_from` uses. Rust's `Master`
   additionally retains viewing and KEM material; those unused fields are
   projected away here.

5. **Dispatcher.** A Rust typed `scan` call has no scheme ID argument.
   `scanEvent` supplies the caller obligation from the prose: the ID must be
   3 and registered. This formal module does not implement other scheme IDs.

6. **Freshness.** The raw deterministic sender cannot enforce global seed
   freshness. `FreshSeeds` states that obligation and `drawIndex` models
   counter consumption. Different counter inputs do not prove different
   SHAKE256 outputs. Different full 64-byte seeds also need not have different
   ephemeral halves. Seed reuse/repeated ephemeral keys can link payments.

## Source and vector mapping

| Model area | Upstream source | Existing vector coverage |
| --- | --- | --- |
| Scalar range, address, point boundary | [crates/ec/src/lib.rs](../crates/ec/src/lib.rs) | V1-02–V1-05, V3-10, V3-12, V3-13 |
| Hash transcripts, offset, sender/scanner/spender | [crates/per-payment/src/lib.rs](../crates/per-payment/src/lib.rs) | V1-01–V1-07; V3-04–V3-08a |
| KEM entry points and implicit rejection | [crates/kem/src/lib.rs](../crates/kem/src/lib.rs) | Vendored NIST ACVP; V3-09, V3-14 |
| Delegation and counter state | [crates/core/src/lib.rs](../crates/core/src/lib.rs) | V3-02/V3-02a and Rust state tests |
| Framing and malformed inputs | [crates/per-payment/src/spec_vectors.rs](../crates/per-payment/src/spec_vectors.rs) | V3-01, V3-03, V3-08, V3-11, V3-15 |

The existing [vector plan](../vectors/PLAN.md) is the traceability reference.
Lean does not rerun ACVP, SHA or curve vectors: those require an instantiated
primitive backend. The Rust and Python vector checks remain necessary.

## Remaining proof obligations

- Instantiate the primitive interface with verified algorithms, and discharge
  the EC laws; prove SEC1 validation completeness and canonicality.
- Prove raw meta-address codec round trips and connect raw keygen/announce
  wrappers to the typed end-to-end theorem.
- Prove a refinement relation from the Rust code to this model, including error
  mapping, seed restoration and actual primitive outputs.
- Formalize probabilistic KEM correctness, recipient-key anonymity, the hybrid
  combiner's security and relevant adversarial games. No such reduction is
  implied by passing a build or by equality of honest shared secrets.
- Model durable wallet state, concurrent callers, seed generation, replay
  deduplication and reorg handling if required by a wallet integration.
- Verify deployed announcer/registry code and transaction behavior separately.

Spending remains ordinary secp256k1 ECDSA, as the repository states. The
delegation window check does not prove non-spendability; computational secrecy
requires cryptographic assumptions. The formal model makes no claim of
post-quantum spending security, side-channel safety or universal gas costs.
