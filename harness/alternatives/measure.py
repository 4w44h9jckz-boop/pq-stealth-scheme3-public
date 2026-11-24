#!/usr/bin/env python3
"""Live gas benchmark for schemeId 3's layout with ML-KEM-768 replaced.

Each configuration in `tools/derive_sizes.ALT_CONFIGS` keeps the secp256k1 half and the
wire layout -- meta-address = spending_pk || viewing_pk_ec || ek..., ephemeralPubKey =
epk || ct..., metadata = view_tag -- and swaps the KEM for FrodoKEM, or for FrodoKEM and
HQC together. No implementation of those schemes exists in this tree, so every row is
CONSTRUCTED: an all-nonzero payload at the derived widths, the same convention as the
classical reference rows. Real key material has about one zero byte in 256, so a real
transaction costs slightly less; `harness/eip7623.py` says by how much.

Per configuration it sends what `harness/payment` and `harness/registration` send: the
announcement, the funding transfer, the spend from the announced address, and a first
registration on the pinned ERC-6538 registry. Anvil's Prague rules do not include EIP-7825,
so a row above the per-transaction cap is still measured; it is flagged, because mainnet
has rejected such a transaction since Fusaka.
"""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from harness.erc5564 import (  # noqa: E402
    ANNOUNCER,
    ANNOUNCER_SHA256,
    install_announcer,
    send_announcement,
)
from harness.evm import (  # noqa: E402
    DEV_ADDRESS,
    DEV_KEY,
    Anvil,
    HARDFORK,
    gas_used,
    load_runtime,
    require_route,
    run,
    send,
    set_code_checked,
)
from harness.registration.measure import (  # noqa: E402
    BYTECODE as REGISTRY_BYTECODE,
    REGISTRY,
    REGISTRY_SHA256,
    Case as RegistrationCase,
    _execute as register,
)
from harness.runner import Benchmark, Context, main_one  # noqa: E402
from tools import derive_sizes  # noqa: E402


OUT = Path(__file__).resolve().parent / "measured.json"
FUND_VALUE = 10**18
SPEND_VALUE = 5 * 10**17
# EIP-7825 (Fusaka): no transaction may use more than 2^24 gas.
EIP_7825_CAP = 2**24
# The rows other than today's have no schemeId. Any id below 256 encodes to the same
# calldata (31 zero bytes and one nonzero), and the event topic costs the same for any value.
PLACEHOLDER_SCHEME_ID = 255


def _nonzero(length: int) -> bytes:
    return bytes(1 + index % 255 for index in range(length))


def _key(tag: int, index: int) -> str:
    return "0x" + f"{tag:02x}" + f"{index + 1:062x}"


def _observation(receipt: dict, calldata: str) -> dict[str, int]:
    raw = bytes.fromhex(calldata.removeprefix("0x"))
    return {
        "calldata_bytes": len(raw),
        "zero_bytes": raw.count(0),
        "gas_used": gas_used(receipt),
    }


def _slug(name: str) -> str:
    return name.lower().replace(" (today)", "").replace(" + ", "_").replace("-", "")


def _payment(url: str, scheme_id: int, epk_field: int, metadata: int,
             index: int) -> dict[str, dict[str, int]]:
    """Announce, fund the announced address, spend from it -- the payment benchmark's
    three transactions, at a constructed shape."""
    spend_key = _key(0xA1, index)
    stealth = run(["cast", "wallet", "address", "--private-key", spend_key]).strip()
    receipt, calldata = send_announcement(
        url,
        scheme_id,
        stealth,
        "0x" + _nonzero(epk_field).hex(),
        "0x" + _nonzero(metadata).hex(),
    )
    fund = send(url, DEV_KEY, "--value", str(FUND_VALUE), stealth)
    require_route(fund, DEV_ADDRESS, stealth, "fund")
    spend = send(url, spend_key, "--value", str(SPEND_VALUE), DEV_ADDRESS)
    require_route(spend, stealth, DEV_ADDRESS, "spend")
    return {
        "announce": _observation(receipt, calldata),
        "fund": {"gas_used": gas_used(fund)},
        "spend": {"gas_used": gas_used(spend)},
    }


def collect(context: Context) -> dict:
    del context  # constructed shapes only; no fixture
    results = []
    with Anvil() as node:
        install_announcer(node.url)
        code = load_runtime(REGISTRY_BYTECODE, REGISTRY_SHA256)
        set_code_checked(node.url, REGISTRY, code, REGISTRY_SHA256)
        for index, (name, (kems, category)) in enumerate(derive_sizes.ALT_CONFIGS.items()):
            _, _, meta, epk_field, metadata, _ = derive_sizes.ALT_SHAPES[name]
            today = kems == ("ML-KEM-768",)
            scheme_id = 3 if today else PLACEHOLDER_SCHEME_ID
            transactions = _payment(node.url, scheme_id, epk_field, metadata, index)
            registration = register(
                node.url,
                RegistrationCase(name, scheme_id, "constructed_shape", _nonzero(meta),
                                 _key(0xB2, index)),
            )
            results.append(
                {
                    "name": _slug(name),
                    "configuration": name,
                    "scheme_id": 3 if today else None,
                    "kind": "constructed_shape",
                    "kems": list(kems),
                    "nist_category": category,
                    "ephemeral_pub_key_bytes": epk_field,
                    "metadata_bytes": metadata,
                    "meta_address_bytes": meta,
                    "transactions": transactions,
                    "registration": registration,
                    "within_eip7825_cap": all(
                        observation["gas_used"] <= EIP_7825_CAP
                        for observation in (*transactions.values(), registration)
                    ),
                }
            )
    return {
        "schema_version": 1,
        "benchmark": "alternatives",
        "environment": {
            "hardfork": HARDFORK,
            "announcer_address": ANNOUNCER,
            "announcer_code_sha256": ANNOUNCER_SHA256,
            "registry_address": REGISTRY,
            "registry_code_sha256": REGISTRY_SHA256,
        },
        "placeholder_scheme_id": PLACEHOLDER_SCHEME_ID,
        "results": results,
    }


def render(artifact: dict) -> str:
    rows = artifact["results"]
    base = rows[0]
    base_announce = base["transactions"]["announce"]["gas_used"]
    base_register = base["registration"]["gas_used"]
    lines = [
        "schemeId 3's layout with the KEM replaced: constructed all-nonzero shapes, "
        f"{artifact['environment']['hardfork'].capitalize()}",
        "",
        f"{'configuration':<24}{'cat':>4}{'announce':>10}{'x':>7}{'payment':>10}"
        f"{'register':>11}{'x':>7}  EIP-7825",
        "-" * 82,
    ]
    for row in rows:
        transactions = row["transactions"]
        announce = transactions["announce"]["gas_used"]
        payment = sum(observation["gas_used"] for observation in transactions.values())
        registration = row["registration"]["gas_used"]
        lines.append(
            f"{row['configuration']:<24}{row['nist_category']:>4}{announce:>10}"
            f"{announce / base_announce:>6.2f}x{payment:>10}{registration:>11}"
            f"{registration / base_register:>6.2f}x  "
            f"{'ok' if row['within_eip7825_cap'] else 'OVER CAP'}"
        )
    lines += ["-" * 82,
              "payment = announce + fund + spend. Ratios are against the first row."]
    return "\n".join(lines)


BENCHMARK = Benchmark("alternatives", OUT, collect, render)


if __name__ == "__main__":
    raise SystemExit(main_one(BENCHMARK))
