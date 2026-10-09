# PQ Stealth Addresses — schemeId 3

Post-quantum stealth addresses for Ethereum: 
one `schemeId` extending [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) 
with an ML-KEM-768 encapsulation combined with a secp256k1 ECDH secret (for implementation risk hedging), 
one announcement per payment, no protocol change.
**Spending stays ordinary secp256k1 ECDSA** - 
hence, the announcement layer is post-quantum, the spending is NOT.

| | |
|---|---|
| meta-address, registered once via ERC-6538 | `spending_pk(33) ‖ viewing_pk_ec(33) ‖ ek(1184)` = **1 250 B** |
| announcement, per payment | `epk ‖ ct` 1 121 B in `ephemeralPubKey`, `view_tag` 1 B in `metadata` = **1 122 B** |
| announcement gas, Prague | **69 330** for the one measured instance |
| first-time registration gas | **964 737** for the measured instance |
| a whole payment (announce, fund, spend) | **111 330** |

The all-nonzero classical baselines are 28 313 gas for a 34 B announcement and 115 310 gas
for a 66 B registration. The registry entry is **18.9x the classical one in bytes** (1 250
against 66) and is paid once per `schemeId`. Against that classical baseline,
Scheme 3 is **2.45x in gas** (69 330 against 28 313) and is paid every time.

See further on [ethresearch](https://ethresear.ch/t/pq-anonymity-for-stealth-address-protocol/26094)
and discuss the draft ERC on [Ethereum Magicians](https://ethereum-magicians.org/t/hybrid-post-quantum-stealth-addresses-erc-5564-schemeid-3/29923).

## What is here

| path | what it is |
|---|---|
| `spec/ERC-VVVV-schemeid3.md` | the specification and ERC *starter* |
| `spec/ethereum-magicians-post.md` | the opening post of the Ethereum Magicians discussion thread |
| `crates/core` | the `StealthScheme` trait |
| `crates/ec` | secp256k1: SEC1 decoding, ECDH, scalar and point addition, the address |
| `crates/kem` | ML-KEM-768, over `ml-kem`, checked against NIST's own ACVP cases |
| `crates/per-payment` | the scheme itself |
| `vectors/` | the fixtures saying what each row pins and which wrong output it distinguishes |
| `harness/` | the gas harnesses: real transactions against a real node, with their receipts |
| `tools/` | fixture generation, size derivation, offline snapshot/document checks, and the ERCs-repository build |
| `contracts/` | a readable ERC-5564 announcer source counterpart; the harness pins deployed runtime bytes |

## Tests

Test with
```bash
cargo test --workspace
python3 tools/run_selftests.py
python3 tools/gen_vectors.py --check
```

`run_selftests.py` runs the four `tools/test-*.py` scripts (sizes, vector generator, snapshot and docs, ERCs-repository build). `gen_vectors.py --check` regenerates `vectors/` and compares it to what is committed. `check_measured.py` is included in `run_selftests.py`.

Gas, against a local Anvil node:

```bash
python3 harness/bench.py all --check
```

The fixtures are generated from `tools/vecprim.py`, 
which is **independent** from the reference implementation that they test. 
spec_vector.rs (implementing the test vectors) in per_payment matches the two implementation outputs for additional correctness check.
For ML-KEM: the ciphertexts are of **NIST's own ACVP file**, vendored at `vectors/tier1/`.

## Submitting to the ERCs repository

The specification here links this repository's files, which do not exist in
[ethereum/ERCs](https://github.com/ethereum/ERCs). `tools/erc_submission.py` writes the copy that
goes there, with other proposals linked as `./eip-N.md`, the copyright line linking
`../LICENSE.md`, and the vectors and their generator as assets. It fails if any link would not
resolve there, and runs `gen_vectors.py --check` on the copied assets. `discussions-to` already
names the
[Ethereum Magicians thread](https://ethereum-magicians.org/t/hybrid-post-quantum-stealth-addresses-erc-5564-schemeid-3/29923).

The editors assign the number after the pull request is opened, so there are two stages. `--out`
is a clone of your fork of ethereum/ERCs.

1. **The draft.** This writes `ERCS/eip-draft_hybrid_pq_stealth_addresses.md`, with no `eip`
   header, and `assets/erc-0/`, which is how unnumbered submissions are laid out:

   ```bash
   python3 tools/erc_submission.py --draft --out path/to/ERCs
   ```

   In the ERCs clone, add a line `nam` to `config/.codespell-whitelist`, since codespell otherwise
   reads the first author's name as a misspelling of "Name". Commit, push to your fork, and open
   a pull request against `master`. Until a number is assigned, the ERCs linter reports the
   missing `eip` header.

2. **Once an editor assigns N.** This writes `ERCS/erc-N.md` and `assets/erc-N/`. EIP-1 makes
   `created` the date of numbering:

   ```bash
   python3 tools/erc_submission.py --number N --created yyyy-mm-dd --out path/to/ERCs
   ```

   Remove the draft files with the `git rm` line it prints, then push to the same pull request.
   Retitle the Magicians thread `ERC-N: ...` and add the pull request to its opening post.

## Kohaku Integration PoC

[Kohaku-ts Plugin](https://github.com/0xakk0r0kamui/kohaku-sapq/tree/pqsa-scheme3/crates/pq-stealth-ts)

[Kohaku-rs Plugin](https://github.com/0xakk0r0kamui/kohaku-sapq-rs/tree/feat/kohaku-stealth/crates/stealth)

## Demo

[Code](https://github.com/0xakk0r0kamui/pq-stealth-scheme3-demo)

[Demo](https://0xakk0r0kamui.github.io/pq-stealth-scheme3-demo/)

[CLI](https://github.com/0xakk0r0kamui/pq-stealth-scheme3-demo-cli)

The TypeScript plugin and the demo predate the current wire layout. They put `ct` in `metadata`,
so their announcements do not interoperate with this tree's until they move `ct` into
`ephemeralPubKey`.

## Licence

Apache-2.0 for the code (`LICENSE`), CC0 for the specification text (`LICENSE-CC0`) per EIP-1.
