#!/usr/bin/env python3
"""Project scan time per announcement for docs/kem-alternatives.md.

    scan_projection.py --speed-kem PATH [--hqc-bench DIR] [--duration N] [--out FILE]

A scanner pays for every announcement it reads, its own or not: ECDH, decapsulation, the
combiner hash, the view tag. This tool times each part on the machine it runs on and
projects the scan of every configuration in `derive_sizes.ALT_CONFIGS`:

- ECDH, SHA3-256 over each combiner input and the rest of the scan come from this tree's
  Rust (`crates/per-payment/examples/scan_timing.rs`). "The rest" is what today's measured
  scan costs beyond its ECDH, decapsulation and combiner hash: parsing, point decoding, the
  view tag. It is carried over unchanged.
- Decapsulation comes from liboqs's `speed_kem`, each KEM with its expanded secret key
  cached, which is how a FrodoKEM scanner has to hold it. Build liboqs with ML-KEM-768,
  FrodoKEM and HQC enabled and pass its `tests/speed_kem`.
- liboqs 0.16.0 carries only HQC's portable reference code, about 25 times slower than
  HQC's own AVX2 build. `--hqc-bench` takes the `tests/bench` directory of the official
  implementation (gitlab.com/pqc-hqc/hqc) built with `-DHQC_ARCH=x86_64
  -DHQC_X86_IMPL=avx256`; its decapsulation cycles are converted with the cycles per
  microsecond `speed_kem` measured on the same machine, and replace liboqs's for HQC.

Timings are of one machine on one day. The output records which, and is not re-checkable
byte for byte the way a gas receipt is.
"""

from __future__ import annotations

import argparse
import datetime
import json
import platform
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))

import derive_sizes  # noqa: E402

DEFAULT_OUT = ROOT / "docs" / "kem-alternatives-scan.json"
TODAY = "ML-KEM-768 (today)"


def liboqs_names(kem: str) -> dict[str, str]:
    """The liboqs algorithm for each FrodoKEM instantiation; one for other KEMs."""
    if kem.startswith("FrodoKEM-"):
        return {"AES": f"{kem}-AES", "SHAKE": f"{kem}-SHAKE"}
    return {"AES": kem, "SHAKE": kem}


def parse_speed_kem(text: str) -> tuple[float, float, str | None]:
    """Mean decapsulation microseconds and cycles from `speed_kem` output, and the liboqs
    version."""
    decaps = None
    for line in text.splitlines():
        cells = [cell.strip() for cell in line.split("|")]
        if cells and cells[0] == "decaps" and len(cells) >= 6:
            if decaps is not None:
                raise ValueError("more than one decaps row; pass one algorithm per run")
            decaps = (float(cells[3]), float(cells[5]))
    if decaps is None:
        raise ValueError("no decaps row in speed_kem output")
    version = re.search(r"OQS version:\s*(\S+)", text)
    return decaps[0], decaps[1], version.group(1) if version else None


def parse_hqc_bench(text: str) -> float:
    """Mean decapsulation cycles from the official HQC `benchmark_kem` output."""
    found = re.findall(r"^Decaps\s*:\s*(\d+)\s+cycles", text, re.M)
    if len(found) != 1:
        raise ValueError(f"expected one Decaps line in HQC benchmark output, found {len(found)}")
    return float(found[0])


def project(rust: dict, decaps_us: dict[str, float]) -> list[dict]:
    """Per configuration: the scan in µs, as specified and with `ek` bound by hash."""
    sha3 = {int(k): v for k, v in rust["sha3_256_us_by_length"].items()}
    today_input = derive_sizes.ALT_COMBINER_INPUT[TODAY][0]
    rest = (rust["scan_foreign_us"] - rust["ecdh_us"]
            - rust["mlkem768_decapsulate_from_seed_us"] - sha3[today_input])
    rows = []
    for name, (kems, category) in derive_sizes.ALT_CONFIGS.items():
        full, hashed = derive_sizes.ALT_COMBINER_INPUT[name]
        row = {"configuration": name, "nist_category": category,
               "combiner_input_bytes": full, "combiner_input_bytes_ek_hashed": hashed}
        for variant in ("AES", "SHAKE"):
            kem_us = sum(decaps_us[liboqs_names(k)[variant]] for k in kems)
            base = rust["ecdh_us"] + kem_us + rest
            row[f"scan_us_{variant.lower()}"] = round(base + sha3[full], 1)
            row[f"scan_us_{variant.lower()}_ek_hashed"] = round(base + sha3[hashed], 1)
        rows.append(row)
    return rows


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--speed-kem", required=True, type=Path)
    parser.add_argument("--hqc-bench", type=Path,
                        help="tests/bench of the official HQC x86_64/avx256 build")
    parser.add_argument("--hqc-version", default="unrecorded version",
                        help="the HQC release that build is, e.g. v5.1.0")
    parser.add_argument("--duration", type=int, default=3)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    lengths = sorted({n for pair in derive_sizes.ALT_COMBINER_INPUT.values() for n in pair})
    rust = json.loads(subprocess.run(
        ["cargo", "run", "--release", "-q", "-p", "pqsa-per-payment", "--example",
         "scan_timing", "--", *map(str, lengths)],
        cwd=ROOT, check=True, capture_output=True, text=True).stdout)

    algorithms = sorted({name for kems, _ in derive_sizes.ALT_CONFIGS.values()
                         for kem in kems for name in liboqs_names(kem).values()})
    liboqs_us, cycles_per_us, version = {}, [], None
    for algorithm in algorithms:
        out = subprocess.run([str(args.speed_kem), "-d", str(args.duration), algorithm],
                             check=True, capture_output=True, text=True).stdout
        us, cycles, found = parse_speed_kem(out)
        liboqs_us[algorithm] = us
        cycles_per_us.append(cycles / us)
        version = version or found
    # The cycle counter runs at a fixed rate; speed_kem measured it against the clock.
    rate = sorted(cycles_per_us)[len(cycles_per_us) // 2]
    decaps = {name: {"us": round(us, 2), "source": f"liboqs {version} speed_kem"}
              for name, us in liboqs_us.items()}
    if args.hqc_bench:
        for name in [a for a in algorithms if a.startswith("HQC-")]:
            exe = args.hqc_bench / f"benchmark_kem_hqc_{name.removeprefix('HQC-')}"
            out = subprocess.run([str(exe)], check=True, capture_output=True, text=True).stdout
            decaps[name] = {"us": round(parse_hqc_bench(out) / rate, 2),
                            "source": f"official HQC implementation {args.hqc_version}, "
                                      "x86_64/avx256"}

    cpu = next((line.split(":", 1)[1].strip()
                for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name")), platform.processor())
    rustc = subprocess.run(["rustc", "--version"], capture_output=True, text=True).stdout
    artifact = {
        "schema_version": 1,
        "date": datetime.date.today().isoformat(),
        "machine": {"cpu": cpu, "cores_used": 1, "os": platform.system()},
        "rustc": rustc.strip(),
        "liboqs": version,
        "rust_scan_timing": rust,
        "cycles_per_us": round(rate, 1),
        "liboqs_decaps_us": {name: round(us, 2) for name, us in liboqs_us.items()},
        "decaps": decaps,
        "projection": project(rust, {name: d["us"] for name, d in decaps.items()}),
    }
    args.out.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")

    print(f"{cpu}; liboqs {version}; one core\n")
    print(f"{'configuration':<24}{'input':>8}{'AES':>9}{'ek hashed':>11}"
          f"{'SHAKE':>9}{'ek hashed':>11}   µs per announcement")
    for row in artifact["projection"]:
        print(f"{row['configuration']:<24}{row['combiner_input_bytes']:>8}"
              f"{row['scan_us_aes']:>9}{row['scan_us_aes_ek_hashed']:>11}"
              f"{row['scan_us_shake']:>9}{row['scan_us_shake_ek_hashed']:>11}")
    print(f"\nmeasured scan today (this tree, seed path): {rust['scan_foreign_us']:.1f} µs"
          f"\nwrote {args.out.relative_to(ROOT) if args.out.is_relative_to(ROOT) else args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
