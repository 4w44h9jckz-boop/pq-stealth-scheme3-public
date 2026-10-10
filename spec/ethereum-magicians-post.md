<!--
The opening post of the Ethereum Magicians thread for spec/ERC-8441-schemeid3.md, posted on
2026-10-09 in the ERCs category and retitled once the number was assigned:
https://ethereum-magicians.org/t/erc-8441-hybrid-post-quantum-stealth-address-scheme/29923
The thread is the live copy. The Draft line below is what the post should carry now: the ERCs
pull request, since the specification's path in this repository changed with the number. The
gas figures below are checked against the committed receipts by tools/check_measured.py, so
rerun it if you edit them.
-->

# Title

ERC-8441: Hybrid post-quantum stealth address scheme

# Body

Hi all. We'd like feedback on a draft ERC that adds a post-quantum scheme to ERC-5564 stealth
addresses.

Draft: https://github.com/ethereum/ERCs/pull/2059
Reference implementation, test vectors and gas harness: https://github.com/namnc/pq-stealth-scheme3-public/tree/main

## Summary

ERC-5564 defines stealth addresses and a `schemeId` namespace, and specifies one scheme,
`schemeId` 1, on secp256k1. This draft specifies `schemeId` 3. Its payment secret combines an
ML-KEM-768 encapsulation with a secp256k1 ECDH secret, so an adversary who later builds a quantum
computer still cannot tell from the public announcement log who was paid, as long as ML-KEM-768
holds.

Spending does not change. Each stealth address is an ordinary secp256k1 EOA. The scheme uses the
deployed ERC-5564 announcer and ERC-6538 registry as they are, with no protocol change and no
new contract.

## Why now

Announcements are public and permanent. Under `schemeId` 1, anyone who can compute discrete
logarithms can take each registered viewing key and work out who every past payment went to. A
quantum computer built later can do this to announcements published today, so the protection
has to be in place before such a computer exists. Theft is different: it needs the quantum
computer while the funds are still there, and spending can migrate separately.

## Design at a glance

- **Keys.** A 128-byte seed gives a spending key, an ECDH viewing key and an ML-KEM-768 seed
  `(d, z)`. The meta-address is `spending_pk || viewing_pk_ec || ek`, 1 250 bytes, registered once
  with ERC-6538. The 96-byte tracking key `viewing_ec || d || z` can be handed to a scanning
  service, which can find payments but not spend them.
- **Payment secret.**
  `ss = SHA3-256(DS || ss_ec || ss_pq || epk || ct || viewing_pk_ec || ek)`. Hashing both shared
  secrets and both ciphertexts keeps it IND-CCA if either component is, without relying on
  anything specific to ML-KEM.
- **Announcement.** `ephemeralPubKey = epk || ct` (1 121 bytes) and `metadata` is the view tag,
  optionally followed by ERC-5564's token metadata. So ERC-5564's metadata layout and its method
  signatures apply unchanged.
- **Offset and view tag.** Both come from separate domain-separated SHA-256 digests of `ss`. The
  view tag is derived after the KEM, because a tag computed from the ECDH secret alone would let
  a quantum adversary rule out most candidate recipients.
- **Sender randomness** comes from a CSPRNG, and encapsulation is plain `ML-KEM.Encaps(ek)`, so
  FIPS-validated ML-KEM libraries work.

## Cost (Prague, measured on a local node against the canonical contracts)

| | announcement | registration, once per recipient |
|---|---|---|
| schemeId 1 (classical) | 28 313 gas | 115 310 gas |
| schemeId 3 | 69 330 gas (2.45x) | 964 737 gas |
| schemeId 3, with ERC-5564 token metadata | 70 550 gas | |

A whole `schemeId` 3 payment (announce, fund and spend) costs 111 330 gas. The `schemeId` 3
announcement sits on the EIP-7623 calldata floor, so its cost is set by calldata size alone. Scanning costs one ECDH, one ML-KEM-768 decapsulation and one hash per
announcement, with no cheaper prefilter.

## What it does not do

It protects the link between an announcement and its recipient, and nothing else. Spending
stays classical. Once a quantum computer exists, a stealth address is exposed as soon as a spend
reveals its public key. The registered spending key also falls, so anyone holding a payment's
`ss`, a delegated scanner included, can spend it. Funds need a separate migration before then.
Funding transfers, sweeps, timing and amounts can still link payments, as in any stealth-address
scheme.

## Where we'd most like feedback

1. **`ct` in `ephemeralPubKey`.** It keeps ERC-5564's metadata and method signatures intact, but
   tools that assume a 33-byte ephemeral key need to dispatch on `schemeId`. Is that acceptable?
2. **The meta-address length.** At 1 250 bytes it does not fit ERC-5564's `n` / `2n` rule. This
   is the one remaining departure from ERC-5564.
3. **KEM anonymity.** The scheme needs ML-KEM-768 ciphertexts not to reveal their recipient
   (ANO-CCA). The published proofs cover round-3 Kyber, and CRYPTREC's ML-KEM evaluation states
   the arguments carry over to ML-KEM. We state it as an assumption. Is anyone aware of a proof
   for ML-KEM as standardised?
4. **The combiner.** It hashes all six inputs instead of following X-Wing, and it is not an
   SP 800-56C approved combiner. Does anyone need NIST approval here?
5. **Downgrade.** A recipient registered under both `schemeId` 1 and 3 can still be paid without
   post-quantum protection by a wallet that only knows `schemeId` 1. The draft makes senders
   that implement `schemeId` 3 prefer it, and advises recipients to register only `schemeId` 3.
6. **Scanning cost.** Every announcement needs a decapsulation before the view tag can be
   checked. How much does that matter for wallets and scanning services?

By Nam Ngo (@namnc), Pierre Daix-Moreux (@dmpierre), kassandra.eth (@kassandraoftroy)
