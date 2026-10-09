"""Canonical ERC-5564 announcer fixture and exact event verification."""

from __future__ import annotations

from pathlib import Path

from harness.evm import (
    DEV_ADDRESS,
    DEV_KEY,
    load_runtime,
    require_route,
    run,
    send,
    set_code_checked,
)


ANNOUNCER = "0x55649E01B5Df198D18D95b5cc5051630cfD45564"
ANNOUNCER_SHA256 = "97b1a2b6e83d4d2d1184c28bfafe24df2463fcaec94e655b2b56ba5fc52a1b17"
BYTECODE = Path(__file__).resolve().parent / "announcement" / "deployed_bytecode.hex"
ANNOUNCE_SIG = "announce(uint256,address,bytes,bytes)"
EVENT_SIG = "Announcement(uint256,address,address,bytes,bytes)"

# ERC-5564's recommended metadata for a native-token transfer, after the view tag: the
# selector `0xeeeeeeee`, the address `0xEeee...EEeE`, then the amount as 32 big-endian bytes.
NATIVE_TOKEN_SELECTOR = bytes.fromhex("eeeeeeee")
NATIVE_TOKEN_ADDRESS = bytes.fromhex("ee" * 20)


def native_token_metadata(amount: int) -> bytes:
    """The 56 bytes ERC-5564 recommends after the view tag for a native-token transfer."""
    return NATIVE_TOKEN_SELECTOR + NATIVE_TOKEN_ADDRESS + amount.to_bytes(32, "big")


def install_announcer(url: str) -> None:
    """Install and read back the canonical announcer runtime."""
    code = load_runtime(BYTECODE, ANNOUNCER_SHA256)
    set_code_checked(url, ANNOUNCER, code, ANNOUNCER_SHA256)


def _topic_uint(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def _topic_address(address: str) -> str:
    return "0x" + "00" * 12 + address[2:].lower()


def _verify_event(
    receipt: dict,
    scheme_id: int,
    stealth_address: str,
    epk: str,
    metadata: str,
) -> None:
    require_route(receipt, DEV_ADDRESS, ANNOUNCER, "announcement")
    caller = str(receipt["from"])
    expected_topics = [
        run(["cast", "keccak", EVENT_SIG]).strip().lower(),
        _topic_uint(scheme_id).lower(),
        _topic_address(stealth_address).lower(),
        _topic_address(caller).lower(),
    ]
    expected_data = run(
        ["cast", "abi-encode", "f(bytes,bytes)", epk, metadata]
    ).strip().lower()
    logs = receipt.get("logs") or []
    if len(logs) != 1:
        raise RuntimeError(f"announcement receipt has {len(logs)} logs, expected one")
    log = logs[0]
    if str(log.get("address", "")).lower() != ANNOUNCER.lower():
        raise RuntimeError("announcement event came from the wrong contract")
    topics = [str(topic).lower() for topic in log.get("topics", [])]
    if topics != expected_topics or str(log.get("data", "")).lower() != expected_data:
        raise RuntimeError("Announcement event does not match the benchmark calldata")


def send_announcement(
    url: str,
    scheme_id: int,
    stealth_address: str,
    epk: str,
    metadata: str,
) -> tuple[dict, str]:
    """Send one canonical announcement and verify its event exactly."""
    calldata = run(
        [
            "cast",
            "calldata",
            ANNOUNCE_SIG,
            str(scheme_id),
            stealth_address,
            epk,
            metadata,
        ]
    ).strip()
    receipt = send(url, DEV_KEY, ANNOUNCER, calldata)
    _verify_event(receipt, scheme_id, stealth_address, epk, metadata)
    return receipt, calldata
