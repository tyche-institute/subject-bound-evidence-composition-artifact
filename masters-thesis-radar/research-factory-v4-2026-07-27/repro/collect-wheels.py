#!/usr/bin/env python3
"""Materialise an offline wheelhouse for the container build.

This run is performed with no network access, so the wheels cannot be
downloaded from an index. They are extracted instead from the local pip HTTP
cache, which holds the authentic PyPI wheel bodies that were used to install
the same versions on the host interpreter.

Each candidate cache body is opened as a zip, its `<name>-<version>.dist-info`
directory is read, and the wheel is accepted only when name and version match
a pin in requirements.txt. The output filename is reconstructed from the
`Tag:` lines of the wheel's own WHEEL metadata (compressed tag set), so the
resulting file is a valid, pip-installable wheel.

Deterministic: no wall-clock, no randomness, sorted iteration, stable output.
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import sys
import zipfile
from collections import OrderedDict


def parse_requirements(path: pathlib.Path) -> "OrderedDict[str, str]":
    pins: "OrderedDict[str, str]" = OrderedDict()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if "==" not in line:
            raise SystemExit(f"requirement is not an exact pin: {raw!r}")
        name, version = line.split("==", 1)
        pins[name.strip().lower().replace("-", "_")] = version.strip()
    return pins


def compressed_tag(wheel_metadata: str) -> str:
    tags = [
        line.split(":", 1)[1].strip()
        for line in wheel_metadata.splitlines()
        if line.startswith("Tag:")
    ]
    if not tags:
        raise ValueError("wheel metadata carries no Tag: line")
    pyabi: "OrderedDict[tuple[str, str], list[str]]" = OrderedDict()
    for tag in tags:
        py, abi, plat = tag.split("-", 2)
        pyabi.setdefault((py, abi), [])
        if plat not in pyabi[(py, abi)]:
            pyabi[(py, abi)].append(plat)
    if len(pyabi) != 1:
        raise ValueError(f"cannot compress heterogeneous tag set: {tags}")
    (py, abi), plats = next(iter(pyabi.items()))
    return f"{py}-{abi}-{'.'.join(plats)}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requirements", required=True)
    parser.add_argument("--cache", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    pins = parse_requirements(pathlib.Path(args.requirements))
    cache = pathlib.Path(args.cache)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    if not cache.is_dir():
        raise SystemExit(f"pip cache directory not found: {cache}")

    found: dict[str, pathlib.Path] = {}
    for body in sorted(cache.rglob("*.body")):
        try:
            with open(body, "rb") as handle:
                if handle.read(2) != b"PK":
                    continue
            archive = zipfile.ZipFile(body)
            names = archive.namelist()
        except Exception:
            continue
        tops = sorted({n.split("/")[0] for n in names})
        for top in tops:
            if not top.endswith(".dist-info"):
                continue
            stem = top[: -len(".dist-info")]
            match = re.fullmatch(r"(?P<name>.+?)-(?P<version>[^-]+)", stem)
            if match is None:
                continue
            key = match.group("name").lower().replace("-", "_")
            version = match.group("version")
            if pins.get(key) != version:
                continue
            if key in found:
                continue
            try:
                meta = archive.read(f"{top}/WHEEL").decode("utf-8")
                tag = compressed_tag(meta)
            except Exception as exc:  # pragma: no cover - defensive
                print(f"skip {body}: {exc}", file=sys.stderr)
                continue
            target = out / f"{match.group('name')}-{version}-{tag}.whl"
            target.write_bytes(body.read_bytes())
            found[key] = target

    missing = sorted(set(pins) - set(found))
    if missing:
        raise SystemExit(
            "wheels not present in the local pip cache and no network is "
            f"available to fetch them: {', '.join(missing)}"
        )

    lines = []
    for key in sorted(found):
        path = found[key]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.name}")
    (out / "WHEELHOUSE-SHA256SUMS").write_text(
        "\n".join(lines) + "\n", encoding="utf-8"
    )
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
