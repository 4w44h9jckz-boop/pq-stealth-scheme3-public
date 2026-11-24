# Replacing ML-KEM-768: FrodoKEM, and FrodoKEM with HQC

A design study, not part of ERC-8441. It asks what the scheme costs if ML-KEM-768 is
replaced by FrodoKEM, or by FrodoKEM and HQC together, keeping everything else.
Gas figures are receipts in `harness/alternatives/measured.json`, apart from EIP-7825's cap,
which is marked where it appears. Byte figures are derived from each specification's
parameters in `tools/derive_sizes.py`.

## Summary

- At today's security category (NIST category 3), the FrodoKEM hybrid costs 657 390 gas per
  announcement and the FrodoKEM + HQC hybrid 1 016 650, against 69 390 today: 9.47x and 14.65x.
- A whole payment (announce, fund, spend) goes from 111 390 gas to 699 390 (6.28x) or
  1 058 650 (9.50x). The two transfers do not change; the announcement is all of the increase.
- First registration goes from 964 809 gas to 11 319 990 (11.73x) or 14 557 546 (15.09x).
  The second is 86.8% of the most gas one transaction may use since Fusaka.
- At category 5, FrodoKEM + HQC cannot be registered at all: its meta-address needs more gas
  than one transaction may use, and ERC-6538 registers a meta-address in one call.
- Scanning costs about 1249 µs per announcement on one core for FrodoKEM-976 + HQC-3 and
  933 µs for FrodoKEM-976, against 85 µs for ML-KEM-768 measured the same way: 14.7x and
  11.0x.

## Why look at this

ML-KEM rests on Module-LWE over a power-of-two cyclotomic ring. Several 2026 results
target that structure. None is a confirmed break as of November 2026:

- A May 2026 preprint by M.-X. Luo claims a polynomial-time quantum attack on Module-LWE
  over power-of-two cyclotomics, naming ML-KEM. It is unreviewed, and a published analysis
  argues that what it recovers is the same for two keys that share a public matrix but have
  different secrets, so it cannot be recovering the secret ([summary](https://hackernoon.com/the-real-cryptography-behind-a-fictional-quantum-machine)).
- D. Simon's claimed polynomial-time quantum algorithm for the dihedral coset problem
  (ePrint 2026/1591) is contradicted by a no-go result from Gupte, Ragavan and Zhandry
  (ePrint 2026/1693) ([summary](https://postquantum.com/security-pqc/simon-quantum-algorithm-lattice-pqc/)).
- Wen and Zheng (CRYPTO 2026) prove Module-LWE equivalent to a structured dihedral coset
  problem. That is a reduction, not an attack ([summary](https://postquantum.com/security-pqc/mlwe-edcp-crypto-2026-ml-kem/)).
- Concrete-hardness papers put the cost of the ring structure at about 1 to 3 bits for
  ML-KEM's parameters ([ePrint 2026/279](https://eprint.iacr.org/2026/279),
  [ePrint 2026/366](https://eprint.iacr.org/2026/366)). The larger gaps they report are for
  sparse-secret parameters used in homomorphic encryption, not for ML-KEM.

What a break would do to this scheme decides whether any of this matters:

- **Funds are never at risk from the KEM.** Spending is secp256k1 plus an offset; learning
  `ss` gives the offset, not the spending key.
- **A classical break of ML-KEM changes nothing.** `ss` also depends on the ECDH secret.
  That is what the hybrid is for.
- **A quantum break is the case that matters.** A quantum computer breaks the ECDH half
  anyway. If ML-KEM also falls to it, every announcement becomes linkable, including every
  past one, because announcements stay on chain. Replacing the KEM later protects only
  payments made after the replacement. A hedge has to be in place before it is needed.

## The two constructions

**FrodoKEM hybrid.** secp256k1 ECDH and FrodoKEM. FrodoKEM is plain LWE: no ring and no
module, so none of the structure that Luo's claim and the concrete-hardness papers use. It
pays for that in size. Germany's BSI and France's ANSSI recommend it as the conservative
lattice choice. It does not escape a break of LWE itself: Simon's claim, had it held, would
have reached plain LWE too.

**FrodoKEM + HQC hybrid.** secp256k1 ECDH, FrodoKEM and HQC. HQC is a code-based KEM
(quasi-cyclic codes), which NIST selected in March 2025 as its backup to ML-KEM because it
rests on different mathematics. Against a quantum attacker, privacy then holds if either
LWE or the HQC code problem holds.

Both use the **salted** FrodoKEM, not eFrodoKEM. A registered `ek` receives a ciphertext
for every payment to that recipient, and the unsalted variant is specified only for fewer
than 2^8 ciphertexts per key
([FrodoKEM security considerations](https://datatracker.ietf.org/doc/draft-longa-cfrg-frodokem-security-considerations/)).

What stays as in schemeId 3:

- The wire layout. The meta-address is `spending_pk || viewing_pk_ec || ek_frodo || ek_hqc`,
  `ephemeralPubKey` is `epk || ct_frodo || ct_hqc`, and `metadata` is the view tag. Without
  HQC, drop its fields.
- The combiner shape: `SHA3-256(DS || ss_ec || ss_frodo || ss_hqc || epk || ct_frodo ||
  ct_hqc || viewing_pk_ec || ek_frodo || ek_hqc)`, with a domain separator naming the new
  scheme. The offset, the range check and the view tag are derived from `ss` exactly as now.
- Spending: ordinary secp256k1 ECDSA.

What changes:

- **A new `schemeId`.** ERC-8441 fixes the KEM and its lengths. Changing them under the
  same id would break every implementation of it. ERC-8441 stays as it is.
- **Keys.** As with ML-KEM's `(d, z)`, the tracking key should hold keygen seeds and
  re-expand them once per scanning session. FrodoKEM's expanded secret key is 19 to 43 KB.
  HQC's decapsulation key is already a 32-byte seed. Section 2.1's key derivation and the
  delegation guard, which compares the tracking key's 32-byte components, need new widths.
- **The combiner input.** It grows from 2 402 B per announcement to about 45 KB for
  FrodoKEM-976 + HQC-3, because `ek` and `ct` are hashed on every scan. Binding
  `SHA3-256(ek)`, computed once per scanner, instead of `ek` itself would nearly halve it;
  the ciphertexts still have to be hashed. In time that is 3 to 5% of a scan.
- **Code.** This tree has no FrodoKEM or HQC implementation. `crates/kem` has a `Kem` trait
  that one would implement; `crates/per-payment` names `MlKem768` directly and would need
  to become generic over it.

## Sizes

Derived in `tools/derive_sizes.py` from FrodoKEM's ISO proposal (2023-03-14) and HQC's
specification (2025-08-22), and asserted against the lengths each publishes.

| KEM | category | `ek` | `ct` | shared secret |
|---|---|---|---|---|
| ML-KEM-768 | 3 | 1 184 B | 1 088 B | 32 B |
| FrodoKEM-640 | 1 | 9 616 B | 9 752 B | 16 B |
| FrodoKEM-976 | 3 | 15 632 B | 15 792 B | 24 B |
| FrodoKEM-1344 | 5 | 21 520 B | 21 696 B | 32 B |
| HQC-1 | 1 | 2 241 B | 4 433 B | 32 B |
| HQC-3 | 3 | 4 514 B | 8 978 B | 32 B |
| HQC-5 | 5 | 7 237 B | 14 421 B | 32 B |

With the secp256k1 half, in the current layout:

| configuration | category | meta-address | announcement | meta-address vs today | announcement vs today |
|---|---|---|---|---|---|
| ML-KEM-768 (today) | 3 | 1 250 B | 1 122 B | 1.0x | 1.0x |
| FrodoKEM-640 | 1 | 9 682 B | 9 786 B | 7.7x | 8.7x |
| FrodoKEM-640 + HQC-1 | 1 | 11 923 B | 14 219 B | 9.5x | 12.7x |
| FrodoKEM-976 | 3 | 15 698 B | 15 826 B | 12.6x | 14.1x |
| FrodoKEM-976 + HQC-3 | 3 | 20 212 B | 24 804 B | 16.2x | 22.1x |
| FrodoKEM-1344 | 5 | 21 586 B | 21 730 B | 17.3x | 19.4x |
| FrodoKEM-1344 + HQC-5 | 5 | 28 823 B | 36 151 B | 23.1x | 32.2x |

The announcement is `ephemeralPubKey` plus the 1-byte view tag.

## Gas

Measured by `harness/alternatives` the way `harness/payment` and `harness/registration`
measure today's scheme: real transactions on a Prague Anvil node, against the same pinned
ERC-5564 announcer and ERC-6538 registry. No implementation exists, so each payload is
constructed: all-nonzero bytes at the derived widths. Real key material has about one zero
byte in 256, which would lower an announcement by up to about 0.3%. Today's row is built the
same way, which is why it reads 69 390 and 964 809 rather than the real sample's 69 330 and
964 737 in the other benchmarks. Re-sent on an Osaka (Fusaka) Anvil node, every receipt is
identical.

| configuration | category | announce gas | vs today | payment gas | registration gas | vs today |
|---|---|---|---|---|---|---|
| ML-KEM-768 (today) | 3 | 69 390 | 1.00x | 111 390 | 964 809 | 1.00x |
| FrodoKEM-640 | 1 | 415 710 | 5.99x | 457 710 | 7 003 401 | 7.26x |
| FrodoKEM-640 + HQC-1 | 1 | 593 180 | 8.55x | 635 180 | 8 610 638 | 8.92x |
| FrodoKEM-976 | 3 | 657 390 | 9.47x | 699 390 | 11 319 990 | 11.73x |
| FrodoKEM-976 + HQC-3 | 3 | 1 016 650 | 14.65x | 1 058 650 | 14 557 546 | 15.09x |
| FrodoKEM-1344 | 5 | 893 710 | 12.88x | 935 710 | 15 544 870 | 16.11x |
| FrodoKEM-1344 + HQC-5 | 5 | 1 470 340 | 21.19x | 1 512 340 | 20 734 366 | 21.49x |

"payment" is announce, fund and spend, as in `harness/payment`. Funding and spending are
plain transfers, so the difference between the two columns is 42 000 gas on every row.

**Announcements are priced by their calldata.** Every announcement above pays exactly
EIP-7623's calldata floor, 21 000 plus 10 gas per calldata token, because emitting the log
costs less than that. A nonzero byte is four tokens, so each byte of ciphertext adds 40 gas.
Projecting any other KEM is a matter of its ciphertext length.

**Registration is priced by storage.** ERC-6538 stores the meta-address, one fresh 32-byte
slot per 32 bytes. Each added meta-address byte costs about 717 gas on every row, against 40
for an announcement byte.

<!-- gas-external: EIP-7825 -->
**The per-transaction cap.** Since Fusaka, EIP-7825 caps one transaction at 16 777 216 gas
(2^24). Anvil 1.5.1 does not enforce it, under Prague or Osaka, so the receipts above
include a row mainnet would reject.

Against that cap, registration uses 67.5% for FrodoKEM-976, 86.8% for FrodoKEM-976 + HQC-3
and 92.7% for FrodoKEM-1344. FrodoKEM-1344 + HQC-5 needs 23.6% more than the cap allows, and
ERC-6538's `registerKeys` takes the whole meta-address in one call, so that configuration
cannot be registered on ERC-6538 at all. The category-3 FrodoKEM + HQC registration has 13%
headroom: a repricing that raised its cost by more than about 15% would put it over too.

**In ETH.** Gas times base fee: at 1 gwei, a payment costs about 1.1 × 10⁻⁴ ETH today,
7.0 × 10⁻⁴ ETH with FrodoKEM-976 and 1.06 × 10⁻³ ETH with FrodoKEM-976 + HQC-3.
Registration, paid once per recipient, costs about 9.6 × 10⁻⁴ ETH today, 1.13 × 10⁻² ETH
and 1.46 × 10⁻² ETH. Scale linearly with the base fee.

## Scanning cost

A scanner does the same work for every announcement, its own or not: ECDH, then
decapsulation, then the combiner hash, and only then the view-tag check. The view tag is
derived from the combined `ss` on purpose: a tag computed from the ECDH secret alone would
let a quantum attacker who breaks ECDH discard 255 of every 256 candidate recipients per
announcement. So the KEM's decapsulation time multiplies directly into scan time.

Projected per announcement, on one core of a 2.1 GHz Xeon with AES-NI and AVX2, by
`tools/scan_projection.py`; the run is recorded in `docs/kem-alternatives-scan.json`.

| configuration | decapsulation (µs) | scan (µs) | `ek` bound by hash (µs) | scan, FrodoKEM-SHAKE (µs) | vs today |
|---|---|---|---|---|---|
| ML-KEM-768 (today) | 15 | 85 | 82 | 85 | 1.0x |
| FrodoKEM-640 | 385 | 497 | 475 | 786 | 5.9x |
| FrodoKEM-640 + HQC-1 | 502 | 634 | 603 | 924 | 7.5x |
| FrodoKEM-976 | 789 | 933 | 893 | 1517 | 11.0x |
| FrodoKEM-976 + HQC-3 | 1074 | 1249 | 1202 | 1833 | 14.7x |
| FrodoKEM-1344 | 1395 | 1570 | 1514 | 2677 | 18.5x |
| FrodoKEM-1344 + HQC-5 | 1972 | 2214 | 2128 | 3320 | 26.1x |

How the projection is built:

- **ECDH, the combiner hash and the rest of the scan** are this tree's Rust, timed by
  `crates/per-payment/examples/scan_timing.rs`. "The rest" (parsing, point decoding, the
  view tag) is what today's measured scan costs beyond its ECDH, decapsulation and hash,
  carried over unchanged.
- **Decapsulation** is timed with the expanded secret key held in memory, which is how a
  FrodoKEM scanner has to hold it. ML-KEM-768 and FrodoKEM come from liboqs 0.16.0, with
  its AVX2 code. HQC comes from the HQC team's own AVX2 build (v5.1.0, which keeps the
  2025-08-22 lengths), because liboqs 0.16.0 carries only HQC's portable reference code:
  2907 µs for an HQC-1 decapsulation there against 117 µs here.
- **Today's row is measured the same way**, so the ratios compare like with like. This
  tree's own scan is slower, 165 µs, because it uses a different ML-KEM implementation and
  re-expands the key from its 64-byte seed on every announcement; the ERC's "about 150 µs"
  is that scan.
- FrodoKEM's SHAKE instantiation is the column to use on hardware without AES instructions.

What the numbers mean:

- **FrodoKEM's decapsulation is most of the cost.** Binding `ek` by its hash saves 3 to 5%.
- **A backlog of a million announcements** takes one core about 21 minutes with
  FrodoKEM-976 + HQC-3 and about 16 with FrodoKEM-976, against under 3 minutes with this
  tree today. Scanning parallelizes across cores and across announcements.
- **Flooding a scanner costs the attacker no less than it does today.** An announcement
  costs about 815 gas per microsecond of scanning it causes, today with the key held in
  memory and with FrodoKEM-976 + HQC-3 alike.
- **Not measured: phones and other ARM hardware.** These figures are one x86 server core.

## Recommendation

1. **Keep ERC-8441 as it is.** Nothing published so far breaks ML-KEM-768, and the ECDH half
   already covers a classical break of it.
2. **If a hedge is wanted, define FrodoKEM-976 + HQC-3 as a separate scheme.** It matches
   today's category and rests on two unrelated post-quantum assumptions. It costs
   1 016 650 gas per announcement, 1 058 650 per payment and 14 557 546 to register, and
   about 1249 µs of scanning per announcement.
3. **FrodoKEM-976 alone** costs 657 390 per announcement and removes only the ring-structure
   concern. Choose it if plain LWE is a sufficient assumption for the hedge.
4. **Do not plan on category 5 with both KEMs.** It cannot be registered on ERC-6538.

Before writing the scheme down:

- Wait for FIPS 207. HQC's lengths have changed between rounds before, and this study uses
  the 2025-08-22 specification.
- Measure scanning on phones and other ARM hardware.
- Choose implementations and test vectors. Both KEMs ship known-answer tests with their
  reference implementations, but neither has NIST ACVP vectors as ML-KEM does; for HQC
  those can only follow FIPS 207.

## Reproduce

```bash
python3 tools/derive_sizes.py                    # the byte figures
python3 harness/bench.py alternatives --check    # the gas figures, against a live Anvil
python3 tools/check_measured.py                  # every gas and byte figure in this file
```

The scan figures are timings of one machine and are re-run rather than re-checked. With
liboqs 0.16.0 built with ML-KEM-768, FrodoKEM and HQC, and the HQC team's implementation
(gitlab.com/pqc-hqc/hqc) built with `-DHQC_ARCH=x86_64 -DHQC_X86_IMPL=avx256`:

```bash
python3 tools/scan_projection.py --speed-kem <liboqs build>/tests/speed_kem \
    --hqc-bench <hqc build>/tests/bench --hqc-version v5.1.0
```

## Sources

- FrodoKEM: [frodokem.org](https://frodokem.org/), and the parameter table in
  [Open Quantum Safe](https://openquantumsafe.org/liboqs/algorithms/kem/frodokem)
- HQC: [pqc-hqc.org](https://pqc-hqc.org/), and NIST's
  [FIPS 207 presentation](https://csrc.nist.gov/csrc/media/presentations/2025/fips-207-hqc-kem/fips_207-robinson_2.4.pdf)
- EIP-7825, [Transaction Gas Limit Cap](https://eips.ethereum.org/EIPS/eip-7825)
- The lattice results above: linked where they are cited
