#!/usr/bin/env python3
"""Self-test for `scan_projection.py`'s parsing and arithmetic.

The tool reads two benchmark formats it does not control, so the cases feed it canned
output of each and check what it extracts: the decapsulation row and nothing else, and a
loud failure when the row is missing or doubled. The projection is checked against a hand
computation from the same inputs, so a change to how the parts add up shows here.

Exit 0 clean, 1 on any failure.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import derive_sizes  # noqa: E402
import scan_projection as sp  # noqa: E402

FAILED: list[str] = []

SPEED_KEM = """\
OQS version:      0.16.0 (major: 0, minor: 16, patch: 0)
Operation                            | Iterations | Total time (s) | Time (us): mean | pop. stdev | CPU cycles: mean          | pop. stdev
------------------------------------ | ----------:| --------------:| ---------------:| ----------:| -------------------------:| ----------:
FrodoKEM-976-AES                     |            |                |                 |            |                           |
keygen                               |       3000 |          3.000 |         900.000 |     10.000 |                   1890000 |      19116
encaps                               |       3000 |          3.000 |         850.000 |     10.000 |                   1785000 |      54907
decaps                               |       3600 |          3.000 |         818.970 |     33.536 |                   1719837 |      70409
"""

HQC_BENCH = """\

--- HQC KEM Benchmark ---
Keygen : 115200 cycles, 0.05 ms
Encaps : 230400 cycles, 0.11 ms
Decaps : 604641 cycles, 0.29 ms

"""


def case(name: str, got, want) -> None:
    if got == want:
        print(f"  ok    {name}")
    else:
        print(f"  FAIL  {name}\n          want: {want!r}\n          got:  {got!r}")
        FAILED.append(name)


def raises(fn, *args) -> bool:
    try:
        fn(*args)
    except ValueError:
        return True
    return False


def main() -> int:
    print("scan_projection self-test")

    print("\nspeed_kem output")
    us, cycles, version = sp.parse_speed_kem(SPEED_KEM)
    case("reads the decaps mean, not keygen's or encaps'", us, 818.97)
    case("and its cycles", cycles, 1719837.0)
    case("and the liboqs version", version, "0.16.0")
    case("no decaps row is an error",
         raises(sp.parse_speed_kem, SPEED_KEM.replace("decaps ", "decapz ")), True)
    case("two decaps rows are an error",
         raises(sp.parse_speed_kem, SPEED_KEM + SPEED_KEM.splitlines()[-1] + "\n"), True)

    print("\nHQC benchmark output")
    case("reads the Decaps cycles", sp.parse_hqc_bench(HQC_BENCH), 604641.0)
    case("no Decaps line is an error",
         raises(sp.parse_hqc_bench, HQC_BENCH.replace("Decaps", "Dec")), True)

    print("\nliboqs names")
    case("FrodoKEM has an AES and a SHAKE instantiation",
         sp.liboqs_names("FrodoKEM-976"),
         {"AES": "FrodoKEM-976-AES", "SHAKE": "FrodoKEM-976-SHAKE"})
    case("other KEMs have one", sp.liboqs_names("HQC-3"), {"AES": "HQC-3", "SHAKE": "HQC-3"})

    print("\nthe projection adds the parts")
    lengths = {n for pair in derive_sizes.ALT_COMBINER_INPUT.values() for n in pair}
    rust = {
        "scan_foreign_us": 160.0, "ecdh_us": 55.0,
        "mlkem768_decapsulate_from_seed_us": 90.0,
        "sha3_256_us_by_length": {str(n): n / 400 for n in lengths},
    }
    decaps = {name: 10.0 * (i + 1) for i, name in enumerate(sorted(
        {a for kems, _ in derive_sizes.ALT_CONFIGS.values()
         for k in kems for a in sp.liboqs_names(k).values()}))}
    rows = {row["configuration"]: row for row in sp.project(rust, decaps)}
    full, hashed = derive_sizes.ALT_COMBINER_INPUT["FrodoKEM-976 + HQC-3"]
    rest = 160.0 - 55.0 - 90.0 - derive_sizes.ALT_COMBINER_INPUT[sp.TODAY][0] / 400
    want = round(55.0 + decaps["FrodoKEM-976-AES"] + decaps["HQC-3"] + rest + full / 400, 1)
    case("FrodoKEM-976 + HQC-3, AES: ECDH + both decapsulations + rest + hash",
         rows["FrodoKEM-976 + HQC-3"]["scan_us_aes"], want)
    want = round(55.0 + decaps["FrodoKEM-976-SHAKE"] + decaps["HQC-3"] + rest
                 + hashed / 400, 1)
    case("and SHAKE with ek bound by hash",
         rows["FrodoKEM-976 + HQC-3"]["scan_us_shake_ek_hashed"], want)
    case("today's row uses the liboqs ML-KEM, not the measured seed path",
         rows[sp.TODAY]["scan_us_aes"],
         round(55.0 + decaps["ML-KEM-768"] + rest
               + derive_sizes.ALT_COMBINER_INPUT[sp.TODAY][0] / 400, 1))

    print()
    if FAILED:
        print(f"FAIL: {len(FAILED)} case(s): {', '.join(FAILED)}")
        return 1
    print("OK: scan_projection behaves as specified.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
