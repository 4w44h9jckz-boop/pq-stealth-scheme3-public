#!/usr/bin/env python3
"""Build the copy of the specification that goes to the ERCs repository.

    erc_submission.py --number N --out DIR [--discussions-to URL] [--created YYYY-MM-DD] [root]

Writes `DIR/ERCS/erc-N.md` and `DIR/assets/erc-N/`, laid out as in a checkout of
github.com/ethereum/ERCs, so DIR can be copied over one. Exit 0 on success, 1 if the result
would not stand in that repository, 2 on a usage error.

WHY A BUILD STEP. `spec/ERC-VVVV-schemeid3.md` links files of this repository, other proposals
on eips.ethereum.org, and this repository's licence. None of those links survives the move:
EIP-1 wants test data under `assets/erc-N/`, the ERCs linter wants other proposals linked as
`./eip-N.md`, and the copyright line must link `../LICENSE.md`. Writing the source in that shape
would break every link here. So the source stays as it is, this applies the mapping, and then
checks that every link in the result resolves in the ERCs repository, which is what that
repository's link checks will do.

The assets copy `vectors/` and `tools/` byte for byte, keeping their layout, so
`python3 tools/gen_vectors.py --check` run in `assets/erc-N/` verifies them there. This script
runs it before reporting success.

What it does not check: the ERCs repository's own linters (eipw, markdownlint, codespell). Run
them in an ERCs checkout, or let its CI run them on the pull request.
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

SPEC = Path("spec/ERC-VVVV-schemeid3.md")
PLACEHOLDER = "VVVV"

# Every file the specification links in this repository, and nothing else. A link to a file
# not listed here is reported, not copied: an asset is something the editors review.
ASSETS = (
    "vectors/PLAN.md",
    "vectors/manifest.json",
    "vectors/section-1.json",
    "vectors/section-2.json",
    "vectors/tier1/ml-kem-768-acvp.json",
    "tools/gen_vectors.py",
    "tools/vecprim.py",
)

LICENSE_HERE = "../LICENSE-CC0"
LICENSE_THERE = "../LICENSE.md"
COPYRIGHT = f"## Copyright\n\nCopyright and related rights waived via [CC0]({LICENSE_THERE}).\n"

LINK = re.compile(r"\]\(([^)\s]+)\)")
EIP_URL = re.compile(r"\(https://eips\.ethereum\.org/EIPS/eip-([0-9]+)\)")
PROPOSAL_LINK = re.compile(r"^\./eip-[0-9]+\.md(#[^\s]*)?$")
# The pattern the ERCs repository's eipw configuration requires of `discussions-to`.
MAGICIANS = re.compile(r"^https://ethereum-magicians\.org/t/[^/]+/[0-9]+$")
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


def set_header(preamble: list[str], name: str, value: str) -> bool:
    """Replace the value of one preamble header. False if the header is absent."""
    for i, line in enumerate(preamble):
        if line.startswith(f"{name}:"):
            preamble[i] = f"{name}: {value}"
            return True
    return False


def convert(text: str, number: int, discussions_to: str | None,
            created: str | None) -> tuple[str, list[str]]:
    """The ERCs-repository text, and what stops it standing there (empty if nothing)."""
    problems: list[str] = []
    lines = text.split("\n")
    if lines[0] != "---" or "---" not in lines[1:]:
        return text, ["no `---` preamble at the top of the specification"]
    end = lines.index("---", 1)
    preamble = lines[1:end]
    if f"eip: {PLACEHOLDER}" not in preamble:
        problems.append(f"preamble has no `eip: {PLACEHOLDER}` line to number")
    set_header(preamble, "eip", str(number))
    if discussions_to is not None and not set_header(preamble, "discussions-to", discussions_to):
        problems.append("preamble has no `discussions-to` header")
    if created is not None and not set_header(preamble, "created", created):
        problems.append("preamble has no `created` header")
    body = "\n".join(lines[end + 1:])

    body = EIP_URL.sub(r"(./eip-\1.md)", body)
    body = body.replace(f"]({LICENSE_HERE})", f"]({LICENSE_THERE})")
    prefix = f"../assets/erc-{number}/"
    for path in ASSETS:
        body = body.replace(f"](../{path})", f"]({prefix}{path})")
    out = "\n".join(["---", *preamble, "---"]) + "\n" + body

    if PLACEHOLDER in out:
        problems.append(f"`{PLACEHOLDER}` is still in the text")
    for target in LINK.findall(body):
        if target.startswith("#") or PROPOSAL_LINK.match(target) or target == LICENSE_THERE:
            continue
        if target.startswith(prefix) and target[len(prefix):] in ASSETS:
            continue
        problems.append(f"link `{target}` does not resolve in the ERCs repository")
    if not out.endswith("\n" + COPYRIGHT):
        problems.append("the file does not end with the Copyright section EIP-1 prescribes")
    return out, problems


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--number", type=int, required=True,
                    help="the number the editors assign")
    ap.add_argument("--out", type=Path, required=True,
                    help="where to write ERCS/ and assets/; an ERCs checkout works")
    ap.add_argument("--discussions-to",
                    help="the Ethereum Magicians thread URL, if not the specification's")
    ap.add_argument("--created", help="yyyy-mm-dd; EIP-1 makes it the date of numbering")
    ap.add_argument("root", nargs="?", type=Path, default=Path("."))
    args = ap.parse_args(argv[1:])
    if args.number <= 0:
        ap.error("--number must be a positive integer")
    if args.created is not None and not DATE.match(args.created):
        ap.error("--created must be yyyy-mm-dd")
    root = args.root.resolve()
    missing = [p for p in (str(SPEC), *ASSETS) if not (root / p).is_file()]
    if missing:
        ap.error(f"not in {root}: {', '.join(missing)}")

    text = (root / SPEC).read_text(encoding="utf-8")
    out, problems = convert(text, args.number, args.discussions_to, args.created)
    if problems:
        print("FAIL: the converted specification would not stand in the ERCs repository:",
              file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    erc = args.out / "ERCS" / f"erc-{args.number}.md"
    assets = args.out / "assets" / f"erc-{args.number}"
    erc.parent.mkdir(parents=True, exist_ok=True)
    erc.write_text(out, encoding="utf-8")
    for path in ASSETS:
        (assets / path).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / path, assets / path)

    # `-B`: importing vecprim would otherwise leave a __pycache__ among the assets.
    check = subprocess.run(
        [sys.executable, "-B", str(assets / "tools/gen_vectors.py"), "--check", str(assets)],
        capture_output=True, text=True,
    )
    if check.returncode != 0:
        print(check.stdout + check.stderr, file=sys.stderr)
        print(f"FAIL: the vectors in {assets} do not re-derive there", file=sys.stderr)
        return 1

    print(f"wrote {erc}")
    print(f"wrote {len(ASSETS)} file(s) under {assets}; gen_vectors.py --check passes there")
    thread = next((ln.split(":", 1)[1].strip() for ln in out.split("\n---\n", 1)[0].split("\n")
                   if ln.startswith("discussions-to:")), "")
    if not MAGICIANS.match(thread):
        print("warning: `discussions-to` is not an Ethereum Magicians thread URL yet, "
              "and the ERCs linter rejects anything else")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
