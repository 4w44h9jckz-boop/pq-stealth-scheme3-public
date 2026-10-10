#!/usr/bin/env python3
"""Self-test for the ERCs-repository build of the specification."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

TOOL = Path(__file__).resolve().parent / "erc_submission.py"
ROOT = TOOL.parent.parent
FAILED: list[str] = []

sys.path.insert(0, str(TOOL.parent))
import erc_submission as es  # noqa: E402

THREAD = "https://ethereum-magicians.org/t/hybrid-post-quantum-stealth-addresses/12345"


def case(name: str, got, want) -> None:
    if got == want:
        print(f"  ok    {name}")
    else:
        print(f"  FAIL  {name}\n          want: {want!r}\n          got:  {got!r}")
        FAILED.append(name)


def run(root: Path, out: Path, *extra: str) -> tuple[int, str]:
    r = subprocess.run(
        [sys.executable, str(TOOL), "--out", str(out), *extra, str(root)],
        capture_output=True, text=True,
    )
    return r.returncode, r.stdout + r.stderr


def tree(tmp: Path) -> Path:
    """A copy of just the files the build reads, so a case can break one."""
    root = tmp / "root"
    for path in (str(es.SPEC), *es.ASSETS):
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / path, root / path)
    return root


def main() -> int:
    print("the committed specification")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "ercs"
        source = (ROOT / es.SPEC).read_text(encoding="utf-8")
        rc, log = run(ROOT, out, "--discussions-to", THREAD, "--created", "2026-10-10")
        case("builds", rc, 0)
        erc = out / "ERCS/erc-8441.md"
        text = erc.read_text(encoding="utf-8") if erc.is_file() else ""
        preamble = text.split("\n---\n", 1)[0]
        case("named and numbered from the specification's `eip` header",
             (erc.is_file(), "\neip: 8441\n" in preamble), (True, True))
        case("discussions-to set", f"\ndiscussions-to: {THREAD}\n" in preamble, True)
        case("created set", "\ncreated: 2026-10-10\n" in preamble, True)
        case("no eips.ethereum.org link left", "eips.ethereum.org" in text, False)
        case("proposals linked relatively", "](./eip-5564.md)" in text, True)
        case("ends with EIP-1's copyright line", text.endswith("\n" + es.COPYRIGHT), True)
        targets = es.LINK.findall(text)
        case("every repository link now points into assets/erc-8441/",
             [t for t in targets if t.startswith("../") and t != es.LICENSE_THERE
              and not t.startswith("../assets/erc-8441/")], [])
        assets = out / "assets/erc-8441"
        case("every asset is a byte-for-byte copy",
             [p for p in es.ASSETS
              if not (assets / p).is_file()
              or (assets / p).read_bytes() != (ROOT / p).read_bytes()], [])
        case("nothing else is written among the assets",
             sorted(str(p.relative_to(assets)) for p in assets.rglob("*") if p.is_file()),
             sorted(es.ASSETS))
        case("the source is left as it is",
             (ROOT / es.SPEC).read_text(encoding="utf-8"), source)

        rc, log = run(ROOT, Path(tmp) / "bare")
        case("without --discussions-to it keeps the specification's thread, and does not warn",
             (rc, "warning: `discussions-to`" in log), (0, False))

    print("\nthe draft files from before the number was assigned")
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "ercs"
        (out / es.DRAFT_ASSETS / "vectors").mkdir(parents=True)
        (out / es.DRAFT_DOC).parent.mkdir(parents=True)
        (out / es.DRAFT_DOC).write_text("---\neip: 0\n---\n", encoding="utf-8")
        rc, log = run(ROOT, out)
        case("are named for removal", (rc, f"git rm -r {es.DRAFT_DOC} {es.DRAFT_ASSETS}" in log),
             (0, True))
        case("are left in place", (out / es.DRAFT_DOC).is_file(), True)
        rc, log = run(ROOT, Path(tmp) / "fresh")
        case("a tree without them names nothing to remove", (rc, "git rm" in log), (0, False))

    print("\nwhat it must refuse")
    with tempfile.TemporaryDirectory() as tmp:
        root = tree(Path(tmp))
        spec = root / es.SPEC
        good = spec.read_text(encoding="utf-8")

        spec.write_text(good.replace("## Security Considerations",
                                     "See [`crates/kem`](../crates/kem).\n\n"
                                     "## Security Considerations"), encoding="utf-8")
        rc, log = run(root, Path(tmp) / "o1")
        case("a link to a file that is not an asset", (rc, "`../crates/kem`" in log), (1, True))

        spec.write_text(good.replace("## Security Considerations",
                                     "See [the paper](https://example.org/paper.pdf).\n\n"
                                     "## Security Considerations"), encoding="utf-8")
        rc, log = run(root, Path(tmp) / "o2")
        case("an external link", (rc, "example.org" in log), (1, True))

        spec.write_text(good.replace("eip: 8441", "eip: VVVV"), encoding="utf-8")
        rc, log = run(root, Path(tmp) / "o3")
        case("a source with no assigned number", (rc, "`VVVV`" in log), (1, True))

        spec.write_text(good + "\nA trailing paragraph.\n", encoding="utf-8")
        rc, log = run(root, Path(tmp) / "o4")
        case("content after the Copyright section", rc, 1)

        spec.write_text(re.sub(r"(?m)^discussions-to: .*$",
                                  "discussions-to: <ethereum-magicians thread, to be opened>",
                                  good), encoding="utf-8")
        rc, log = run(root, Path(tmp) / "o6")
        case("a placeholder thread builds, with a warning",
             (rc, "warning: `discussions-to`" in log), (0, True))

        spec.write_text(good, encoding="utf-8")
        vec = root / "vectors/section-1.json"
        vec.write_bytes(vec.read_bytes().replace(b"d8b37e9f", b"d8b37e90", 1))
        rc, log = run(root, Path(tmp) / "o5")
        case("a vector that no longer re-derives", (rc, "do not re-derive" in log), (1, True))

    print("\nusage")
    with tempfile.TemporaryDirectory() as tmp:
        for name, argv in (
            ("no --out", []),
            ("the retired --draft", ["--draft", "--out", tmp]),
            ("a malformed --created", ["--out", tmp, "--created", "10/10/26"]),
            ("a root with no specification", ["--out", tmp, tmp]),
        ):
            r = subprocess.run([sys.executable, str(TOOL), *argv], capture_output=True,
                               text=True, cwd=ROOT)
            case(f"{name} exits 2", r.returncode, 2)

    print()
    if FAILED:
        print(f"FAIL: {len(FAILED)} case(s): {', '.join(FAILED)}")
        return 1
    print("OK: erc_submission builds the committed specification and refuses what would not "
          "stand in the ERCs repository.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
