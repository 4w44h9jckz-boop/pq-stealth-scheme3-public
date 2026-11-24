#!/usr/bin/env python3
"""Re-derive this document's byte figures from FIPS 203 and from §3's wire rules.

The alternative-KEM section near the end does the same for docs/kem-alternatives.md: FrodoKEM's
and HQC's lengths from their parameters, and the shapes they give in schemeId 3's layout.

**What it covers, and what it does not.** It checks the figures listed in its own tables:
the announcement payloads and their field splits, the meta-addresses, the registration
ratios, and the delegation component count. **It does not scan the documents for figures it
has not been told about** -- so a new byte figure is unchecked until someone adds it here,
and the closing line says so rather than claiming "every quoted figure"; that claim over
partial coverage would be an overclaimed figure inside the harness built to remove
overclaimed figures.

**Why this file exists.** Rule #54 of this project's method is that a figure in a document
must have a committed harness -- a number whose generator no longer exists is
unfalsifiable, which is worse than an absent number. `harness/announcement/measure.py`
reads its field lengths from here rather than retyping them, because a retyped copy of a
wire table can carry a superseded view-tag width while looking complete.

**This derivation is deliberately independent of the code that produced the numbers.** It
computes `ek` from FIPS 203's formula rather than from the constant 1 184, then asserts
agreement with it. Re-deriving from the constant that produced a figure proves only that
copying worked.

Run: `python3 tools/derive_sizes.py`   Exit 0 if every figure agrees, 1 otherwise.
"""

from __future__ import annotations

import sys

# ---- FIPS 203 (ML-KEM-768) -----------------------------------------------------------
MLKEM_768_K = 3
MLKEM_768_DU = 10
MLKEM_768_DV = 4
EK = 384 * MLKEM_768_K + 32
CT = 32 * (MLKEM_768_DU * MLKEM_768_K + MLKEM_768_DV)
DK_EXPANDED = 768 * MLKEM_768_K + 96      # not used on the wire; see the seed note below
CT_MLKEM768 = CT

# FIPS 203's own stated lengths for ML-KEM-768, asserted against the formulas above. If the
# two ever disagree, one of them is wrong and the failure should be loud.
FIPS_203_EK = 1_184
FIPS_203_CT = 1_088

# ---- §3's wire rules -----------------------------------------------------------------
SEC1_COMPRESSED = 33      # secp256k1 point, SEC1 compressed, per §1
VIEW_TAG = 1              # §3 rule 1: the FIRST BYTE of `metadata`, in EVERY announcement.
                          # One, everywhere; there is no confirm tag. It was eight until the
                          # announced `stealthAddress` was made the authoritative check
                          # (§2.5 MUST) and the tag was narrowed to a prefilter.
SCALAR = 32               # a secp256k1 scalar, or a 32-byte seed
# ERC-5564's recommended token metadata after the view tag: a 4-byte function selector, a
# 20-byte token address and a 32-byte amount. Optional in `schemeId` 3 (§3 rule 3).
TOKEN_METADATA = 4 + 20 + 32
SPENDING_PK = 33          # secp256k1, SEC1 compressed
VIEWING_PK_EC = 33

# Each is stated as its construction so that a change to one field cannot leave a total
# behind.
ANNOUNCE_ERC = {
    "schemeId 3 announcement":  (SEC1_COMPRESSED + CT + VIEW_TAG,     1_122),
    "schemeId 3 announcement, token metadata":
        (SEC1_COMPRESSED + CT + VIEW_TAG + TOKEN_METADATA,            1_178),
}

# §3's shape is the PAIR of field lengths, not the total, and the distinction is
# load-bearing: two schemes can share a total and still be distinguishable, because one puts
# `ct` in `ephemeralPubKey` and the other in `metadata`. Modelling the total alone would
# call that a collision.
#
# (`ephemeralPubKey`, `metadata`) per row. `ct` rides in `ephemeralPubKey` after `epk`, so
# `metadata` is ERC-5564's own: the view tag, which is all the reference sender emits, and
# optionally ERC-5564's token metadata after it.
SHAPES = {
    "schemeId 3 announcement":  (SEC1_COMPRESSED + CT,  VIEW_TAG),
    "schemeId 3 announcement, token metadata":
        (SEC1_COMPRESSED + CT,  VIEW_TAG + TOKEN_METADATA),
}

# The `schemeId` each shape belongs to, so the gas harness can address them. Stated here
# rather than parsed out of the key: a name is prose and an id is a wire field, and the
# ERC-5564 registry is a namespace where getting one wrong publishes material under another
# scheme.
SHAPE_SCHEME_ID = {
    "schemeId 3 announcement": 3,
    "schemeId 3 announcement, token metadata": 3,
}

# Pairs this tree declares indistinguishable by length. Asserted rather than left as a
# coincidence, and any UNDECLARED pair sharing a shape is a failure -- recognition is by
# `schemeId` plus the field lengths, so a collision is not a conformance defect, but one
# that appeared without anyone writing it down would mean §3's recognition rule had gone
# stale. Empty here, and the detector below is what keeps it honest.
DECLARED_SHAPE_COLLISIONS: list[tuple[str, str]] = []

# The delegation guard of §2.1 compares `spending_seed` with each 32-byte COMPONENT of the
# tracking key -- `viewing_ec_seed`, `d`, `z` -- so the count is (len / 32). It used to scan
# every 32-byte window, (len - 32 + 1) = 65 of them; the windows that straddle a component
# boundary can only match under a derivation that is already broken, so they were dropped in
# favour of the independence requirement that actually covers that case.
DELEGATION = {
    "schemeId 3 (viewing_ec(32) || d(32) || z(32) = 96 B)": (96 // SCALAR, 3),
}

META = {
    "schemeId 3": (SPENDING_PK + VIEWING_PK_EC + EK,   1_250),
}

# The registration table under Rationale, Cost. `schemeId 1`'s 66 B is ERC-5564's own meta-address -- two
# SEC1-compressed points -- and is the baseline every ratio in that column is against. The
# ratios are checked here rather than trusted because they are the only figures in that
# table nobody measured OR quoted from elsewhere: they were computed while writing it, which
# is exactly the case rule #54 covers.
META_CLASSICAL = 2 * SPENDING_PK          # ERC-5564 schemeId 1: spending || viewing
REGISTRATION_RATIOS = {
    "1": (META_CLASSICAL, "1.0"),
    "3": (1_250, "18.9"),
}

# WHAT THE WORST-CASE CALLDATA CONVENTION OVERSTATES BY, derived rather than described.
#
# `harness/registration` registers an ALL-NONZERO payload, which is stated as a worst case.
# Real key material is not all-nonzero, so every registration figure is an upper bound --
# and the size of the gap is arithmetic, not a judgement call. It lived in prose as "a few
# hundred gas" while the largest row was several times longer than this scheme's 1 250 B;
# at 1 250 B it is an order of magnitude smaller, and prose is where that kind of drift
# survives a resize. Rule #54: the figure gets a generator.
#
# EIP-7623 prices calldata in tokens -- a zero byte is one, a nonzero byte is four.
# Registration is STORAGE-dominated, so the standard path binds (the 7623 floor sits an
# order of magnitude below these receipts) and a token costs 4 gas there. A byte that turns
# out to be zero therefore costs (4 - 1) * 4 gas less, and one byte in 256 of real key
# material is zero.
#
# Storage is NOT part of this: a payload byte reaches SSTORE's zero-value price only through
# an all-zero 32-byte slot, which real key material gives with probability 2**-256 per full
# slot. The one exception is a payload whose length is not a multiple of 32 -- schemeId 3's
# 1 250 B leaves a 2-byte tail sharing its slot with 30 bytes of zero padding, so that slot
# is all-zero with probability 2**-16. Worth about 0.3 gas in expectation, which is why it
# is a note and not a term.
EIP_7623_TOKEN_GAS_STANDARD = 4
EIP_7623_TOKENS_PER_NONZERO_BYTE = 4
EIP_7623_TOKENS_PER_ZERO_BYTE = 1
ZERO_BYTE_SAVING = ((EIP_7623_TOKENS_PER_NONZERO_BYTE - EIP_7623_TOKENS_PER_ZERO_BYTE)
                    * EIP_7623_TOKEN_GAS_STANDARD)
ZERO_BYTE_ODDS = 256
# The overstatement quoted per schemeId, in gas, by the harness that applies the
# convention -- `harness/registration/measure.py`'s `blob()`. Checked below, not trusted.
REGISTRATION_OVERSTATEMENT = {"1": 3, "3": 59}

# ---- Alternative KEMs, for docs/kem-alternatives.md ----------------------------------
# Not part of the specification. These are the shapes `harness/alternatives` measures if
# ML-KEM-768 is replaced by FrodoKEM, or by FrodoKEM and HQC together, keeping the
# secp256k1 half and the layout of schemeId 3. Same discipline as FIPS 203 above: each
# length is computed from its specification's parameters and asserted against the length
# that specification publishes.
#
# FrodoKEM, ISO preliminary standardization proposal (2023-03-14), the SALTED variant: a
# registered `ek` is reused for every payment, and the unsalted eFrodoKEM is limited to
# fewer than 2^8 ciphertexts per key. (n, D, len_salt bits, shared-secret bits, category);
# nbar = mbar = 8, seedA = 128 bits.
#   ek = seedA/8 + D*n*nbar/8        ct = (mbar*n*D + mbar*nbar*D)/8 + len_salt/8
FRODO_NBAR = 8
FRODO_SEED_A = 16
FRODO_PARAMS = {
    "FrodoKEM-640":  (640, 15, 256, 128, 1),
    "FrodoKEM-976":  (976, 16, 384, 192, 3),
    "FrodoKEM-1344": (1344, 16, 512, 256, 5),
}
FRODO_PUBLISHED = {            # (ek, ct, ss) bytes, from the proposal's parameter table
    "FrodoKEM-640":  (9_616, 9_752, 16),
    "FrodoKEM-976":  (15_632, 15_792, 24),
    "FrodoKEM-1344": (21_520, 21_696, 32),
}
# HQC, specification of 2025-08-22 (the version NIST is drafting FIPS 207 from).
# (n, n1, n2, category); ek = seed(32) || s, ct = u || v || salt(16), ss = 32.
#   ek = 32 + ceil(n/8)              ct = ceil(n/8) + ceil(n1*n2/8) + 16
HQC_SEED_EK = 32
HQC_SALT = 16
HQC_SS = 32
HQC_PARAMS = {
    "HQC-1": (17_669, 46, 384, 1),
    "HQC-3": (35_851, 56, 640, 3),
    "HQC-5": (57_637, 90, 640, 5),
}
HQC_PUBLISHED = {              # (ek, ct, ss) bytes, from the specification's parameter table
    "HQC-1": (2_241, 4_433, 32),
    "HQC-3": (4_514, 8_978, 32),
    "HQC-5": (7_237, 14_421, 32),
}


def _frodo(n: int, d: int, salt_bits: int, ss_bits: int) -> tuple[int, int, int]:
    ek = FRODO_SEED_A + d * n * FRODO_NBAR // 8
    ct = (FRODO_NBAR * n * d + FRODO_NBAR * FRODO_NBAR * d) // 8 + salt_bits // 8
    return ek, ct, ss_bits // 8


def _hqc(n: int, n1: int, n2: int) -> tuple[int, int, int]:
    vector = -(-n // 8)
    return HQC_SEED_EK + vector, vector + -(-(n1 * n2) // 8) + HQC_SALT, HQC_SS


ALT_KEM_SIZES = {name: _frodo(*params[:4]) for name, params in FRODO_PARAMS.items()}
ALT_KEM_SIZES.update({name: _hqc(*params[:3]) for name, params in HQC_PARAMS.items()})
ALT_KEM_SIZES["ML-KEM-768"] = (EK, CT, SCALAR)

# Each configuration keeps schemeId 3's layout: meta-address = spending_pk || viewing_pk_ec
# || ek..., ephemeralPubKey = epk || ct..., metadata = view_tag. (KEMs, NIST category.)
ALT_CONFIGS = {
    "ML-KEM-768 (today)":    (("ML-KEM-768",), 3),
    "FrodoKEM-640":          (("FrodoKEM-640",), 1),
    "FrodoKEM-640 + HQC-1":  (("FrodoKEM-640", "HQC-1"), 1),
    "FrodoKEM-976":          (("FrodoKEM-976",), 3),
    "FrodoKEM-976 + HQC-3":  (("FrodoKEM-976", "HQC-3"), 3),
    "FrodoKEM-1344":         (("FrodoKEM-1344",), 5),
    "FrodoKEM-1344 + HQC-5": (("FrodoKEM-1344", "HQC-5"), 5),
}


def _alt_shape(kems: tuple[str, ...]) -> tuple[int, int, int, int, int, int]:
    ek = sum(ALT_KEM_SIZES[k][0] for k in kems)
    ct = sum(ALT_KEM_SIZES[k][1] for k in kems)
    return (ek, ct, SPENDING_PK + VIEWING_PK_EC + ek,
            SEC1_COMPRESSED + ct, VIEW_TAG, SEC1_COMPRESSED + ct + VIEW_TAG)


# (ek total, ct total, meta-address, ephemeralPubKey, metadata, announcement) bytes.
ALT_SHAPES = {name: _alt_shape(kems) for name, (kems, _) in ALT_CONFIGS.items()}


def _alt_combiner_input(kems: tuple[str, ...]) -> int:
    """ss_ec || ss_pq... || epk || ct... || viewing_pk_ec || ek..., as §1.1's combiner."""
    return (SCALAR + sum(ALT_KEM_SIZES[k][2] for k in kems) + SEC1_COMPRESSED
            + sum(ALT_KEM_SIZES[k][1] for k in kems) + VIEWING_PK_EC
            + sum(ALT_KEM_SIZES[k][0] for k in kems))


# Bytes hashed per scanned announcement: as specified, and with `ek` bound by its 32-byte
# SHA3-256 instead, computed once per scanner.
ALT_COMBINER_INPUT = {
    name: (_alt_combiner_input(kems), _alt_combiner_input(kems) - ALT_SHAPES[name][0] + SCALAR)
    for name, (kems, _) in ALT_CONFIGS.items()
}


def main() -> int:
    bad: list[str] = []

    print("ML-KEM-768 lengths, from FIPS 203's formulas")
    print(f"  ek = 384*{MLKEM_768_K} + 32          = {EK} B   (FIPS 203: {FIPS_203_EK})")
    print(f"  ct = 32*({MLKEM_768_DU}*{MLKEM_768_K} + {MLKEM_768_DV})          "
          f"= {CT} B   (FIPS 203: {FIPS_203_CT})")
    if EK != FIPS_203_EK:
        bad.append(f"ek {EK} != FIPS 203's {FIPS_203_EK}")
    if CT != FIPS_203_CT:
        bad.append(f"ct {CT} != FIPS 203's {FIPS_203_CT}")

    print("\nthe announcement payloads, from the same primitives")
    for name, (derived, quoted) in ANNOUNCE_ERC.items():
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  {name:<42}{derived:>6} B   spec {quoted:>6}   {mark}")
        if derived != quoted:
            bad.append(f"{name}: derived {derived} != quoted {quoted}")

    print("\nshapes are (ephemeralPubKey, metadata) -- the pair, which is what §3 "
          "recognises on")
    for name, (epk_len, md_len) in SHAPES.items():
        total = epk_len + md_len
        quoted = ANNOUNCE_ERC[name][1]
        mark = "ok" if total == quoted else "MISMATCH"
        print(f"  {name:<42}({epk_len:>4}, {md_len:>5})  = {total:>5} B   "
              f"spec {quoted:>5}   {mark}")
        if total != quoted:
            bad.append(f"{name}: shape ({epk_len}, {md_len}) totals {total} != §3's {quoted}")

    by_shape: dict[tuple[int, int], list[str]] = {}
    for name, shape in SHAPES.items():
        by_shape.setdefault(shape, []).append(name)
    declared = {frozenset(pair) for pair in DECLARED_SHAPE_COLLISIONS}
    for shape, names in sorted(by_shape.items()):
        if len(names) < 2:
            continue
        if frozenset(names) in declared:
            print(f"  declared collision at {shape}: {' == '.join(sorted(names))}   ok")
        else:
            bad.append(f"UNDECLARED shape collision at {shape}: {', '.join(sorted(names))} -- "
                       f"record it in §3 and in DECLARED_SHAPE_COLLISIONS, or separate them")
    for pair in DECLARED_SHAPE_COLLISIONS:
        if SHAPES[pair[0]] != SHAPES[pair[1]]:
            bad.append(f"§3 declares {pair[0]} and {pair[1]} the same shape and they are "
                       f"{SHAPES[pair[0]]} and {SHAPES[pair[1]]}")

    print("\ndelegation components compared -- (len / 32), one per 32-byte component")
    for name, (derived, quoted) in DELEGATION.items():
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  {derived:>4} components   spec {quoted:>4}   {mark}   {name}")
        if derived != quoted:
            bad.append(f"{name}: derived {derived} components != quoted {quoted}")

    print("\nmeta-addresses, from §2.2's registry column")
    for name, (derived, quoted) in META.items():
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  {name:<28}{derived:>6} B   spec {quoted:>6}   {mark}")
        if derived != quoted:
            bad.append(f"{name} meta-address: derived {derived} != quoted {quoted}")

    print(f"\nregistration calldata, per the cost table, against schemeId 1's "
          f"{META_CLASSICAL} B")
    for name, (size, quoted) in REGISTRATION_RATIOS.items():
        derived = f"{size / META_CLASSICAL:.1f}"
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  schemeId {name:<16}{size:>6} B   {derived:>6}x   spec {quoted:>6}x   {mark}")
        if derived != quoted:
            bad.append(f"schemeId {name} registration ratio: derived {derived} "
                       f"!= quoted {quoted}")

    print(f"\nwhat the all-nonzero registration payload overstates by: a zero calldata "
          f"byte is\n  {ZERO_BYTE_SAVING} gas cheaper on EIP-7623's standard path, and "
          f"1 byte in {ZERO_BYTE_ODDS} of real key material is zero")
    for name, (size, _) in REGISTRATION_RATIOS.items():
        derived = round(size / ZERO_BYTE_ODDS * ZERO_BYTE_SAVING)
        quoted = REGISTRATION_OVERSTATEMENT[name]
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  schemeId {name:<16}{size:>6} B   ~{derived:>4} gas   "
              f"docs ~{quoted:>4} gas   {mark}")
        if derived != quoted:
            bad.append(f"schemeId {name} registration overstatement: derived {derived} "
                       f"!= quoted {quoted}")

    # The tracking key is the SEED pair, not the expanded decapsulation key. Stated because
    # the difference is 64 bytes against 2 400 and the specification leans on it.
    print(f"\ntracking key is ML-KEM's (d, z) seed pair at 64 B, not the expanded "
          f"decapsulation key at {DK_EXPANDED} B")

    print("\nalternative KEMs (docs/kem-alternatives.md), from their parameters")
    published = {**FRODO_PUBLISHED, **HQC_PUBLISHED}
    for name, quoted in published.items():
        derived = ALT_KEM_SIZES[name]
        mark = "ok" if derived == quoted else "MISMATCH"
        print(f"  {name:<14} (ek, ct, ss) = {derived}   published {quoted}   {mark}")
        if derived != quoted:
            bad.append(f"{name}: derived (ek, ct, ss) {derived} != published {quoted}")
    print("  with secp256k1, in schemeId 3's layout: meta-address, ephemeralPubKey, metadata")
    for name, (_, _, meta, epk_field, md, total) in ALT_SHAPES.items():
        print(f"  {name:<24}{meta:>7} B {epk_field:>7} B {md:>3} B   announcement {total:>6} B")
    if ALT_SHAPES["ML-KEM-768 (today)"][2:5] != (META["schemeId 3"][1],
                                               *SHAPES["schemeId 3 announcement"]):
        bad.append("the ML-KEM-768 row of ALT_SHAPES is not schemeId 3's shape")
    print("  combiner input per scanned announcement, and with ek bound by its hash")
    for name, (full, hashed) in ALT_COMBINER_INPUT.items():
        print(f"  {name:<24}{full:>7} B {hashed:>7} B")
    today = 2 * SCALAR + 2 * SEC1_COMPRESSED + CT + EK
    if ALT_COMBINER_INPUT["ML-KEM-768 (today)"][0] != today:
        bad.append(f"the ML-KEM-768 combiner input is not §1.1's {today} B")

    print()
    if bad:
        print(f"FAIL: {len(bad)} disagreement(s)")
        for b in bad:
            print("  " + b)
        return 1
    print("OK: every figure listed above re-derives from FIPS 203, from §3's wire rules, and for\n"
          "    the alternative KEMs from their own specifications' parameters.\n"
          "    Coverage is what this file enumerates and no more -- it does NOT sweep the "
          "documents for\n    byte figures it has not been told about. A figure nobody adds "
          "here is a figure nobody checks.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
