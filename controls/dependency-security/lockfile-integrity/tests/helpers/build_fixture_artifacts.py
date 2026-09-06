#!/usr/bin/env python3
"""Build deterministic inert npm tarballs and Python wheels for native tests."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import shutil
import tarfile
import zipfile


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("--tampered-leaf", action="store_true")
    return parser.parse_args()


def npm_tarball(
    destination: Path,
    *,
    name: str,
    version: str,
    dependencies: dict[str, str] | None = None,
    os_names: list[str] | None = None,
    marker: str = "reviewed",
) -> None:
    package_json: dict[str, object] = {
        "name": name,
        "version": version,
        "main": "index.js",
    }
    if dependencies:
        package_json["dependencies"] = dependencies
    if os_names:
        package_json["os"] = os_names

    files = {
        "package/package.json": (
            json.dumps(package_json, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8"),
        "package/index.js": (
            '"use strict";\n\n'
            f'module.exports = {json.dumps({"marker": marker, "name": name, "version": version})};\n'
        ).encode("utf-8"),
    }

    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as raw_output:
        with gzip.GzipFile(fileobj=raw_output, mode="wb", filename="", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.GNU_FORMAT) as archive:
                for filename, content in sorted(files.items()):
                    entry = tarfile.TarInfo(filename)
                    entry.size = len(content)
                    entry.mode = 0o644
                    entry.mtime = 0
                    entry.uid = 0
                    entry.gid = 0
                    entry.uname = ""
                    entry.gname = ""
                    archive.addfile(entry, io.BytesIO(content))


def record_hash(content: bytes) -> str:
    digest = hashlib.sha256(content).digest()
    encoded = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    return f"sha256={encoded}"


def wheel(
    destination: Path,
    *,
    distribution: str,
    version: str,
    requires_dist: list[str] | None = None,
    marker: str = "reviewed",
) -> None:
    module_name = distribution.replace("-", "_")
    dist_info = f"{module_name}-{version}.dist-info"
    metadata_lines = [
        "Metadata-Version: 2.1",
        f"Name: {distribution}",
        f"Version: {version}",
    ]
    for requirement in requires_dist or []:
        metadata_lines.append(f"Requires-Dist: {requirement}")

    files: dict[str, bytes] = {
        f"{module_name}/__init__.py": (
            f'__version__ = "{version}"\nMARKER = "{marker}"\n'
        ).encode("utf-8"),
        f"{dist_info}/METADATA": ("\n".join(metadata_lines) + "\n").encode("utf-8"),
        f"{dist_info}/WHEEL": (
            "Wheel-Version: 1.0\n"
            "Generator: psb-lockfile-integrity-fixture\n"
            "Root-Is-Purelib: true\n"
            "Tag: py3-none-any\n"
        ).encode("utf-8"),
    }
    record_path = f"{dist_info}/RECORD"
    record_lines = [
        f"{filename},{record_hash(content)},{len(content)}"
        for filename, content in sorted(files.items())
    ]
    record_lines.append(f"{record_path},,")
    files[record_path] = ("\n".join(record_lines) + "\n").encode("utf-8")

    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for filename, content in sorted(files.items()):
            info = zipfile.ZipInfo(filename, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, content)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    args = parse_args()
    npm_directory = args.output / "npm"
    python_directory = args.output / "python"

    leaf_tarball = npm_directory / "psb-leaf-1.0.0.tgz"
    parent_tarball = npm_directory / "psb-parent-1.0.0.tgz"
    linux_tarball = npm_directory / "psb-linux-only-1.0.0.tgz"
    npm_tarball(
        leaf_tarball,
        name="@psb/leaf",
        version="1.0.0",
        marker="tampered" if args.tampered_leaf else "reviewed",
    )
    npm_tarball(
        parent_tarball,
        name="@psb/parent",
        version="1.0.0",
        dependencies={"@psb/leaf": leaf_tarball.resolve().as_uri()},
    )
    npm_tarball(
        linux_tarball,
        name="@psb/linux-only",
        version="1.0.0",
        os_names=["linux"],
    )

    javascript_projects = args.output / "projects" / "javascript"
    replacements = {
        "__PSB_LEAF_TARBALL__": leaf_tarball.resolve().as_posix(),
        "__PSB_PARENT_TARBALL__": parent_tarball.resolve().as_posix(),
        "__PSB_LINUX_TARBALL__": linux_tarball.resolve().as_posix(),
    }
    for fixture_name in ("basic", "transitive-change", "platform-optional"):
        source_directory = args.fixture_root / "javascript" / fixture_name
        target_directory = javascript_projects / fixture_name
        target_directory.mkdir(parents=True, exist_ok=True)
        for source in source_directory.glob("*.json"):
            content = source.read_text(encoding="utf-8")
            for token, value in replacements.items():
                content = content.replace(token, value)
            (target_directory / source.name).write_text(content, encoding="utf-8")

    shutil.copytree(
        args.fixture_root / "javascript" / "workspace",
        javascript_projects / "workspace",
    )

    leaf_wheel = python_directory / "psb_leaf-1.0.0-py3-none-any.whl"
    parent_wheel = python_directory / "psb_parent-1.0.0-py3-none-any.whl"
    wheel(
        leaf_wheel,
        distribution="psb-leaf",
        version="1.0.0",
        marker="tampered" if args.tampered_leaf else "reviewed",
    )
    wheel(
        parent_wheel,
        distribution="psb-parent",
        version="1.0.0",
        requires_dist=["psb-leaf==1.0.0"],
    )

    simple_directory = args.output / "simple"
    for project_name, wheel_path in (
        ("psb-leaf", leaf_wheel),
        ("psb-parent", parent_wheel),
    ):
        project_directory = simple_directory / project_name
        project_directory.mkdir(parents=True, exist_ok=True)
        wheel_url = wheel_path.resolve().as_uri()
        project_directory.joinpath("index.html").write_text(
            (
                "<!doctype html><html><body>"
                f'<a href="{wheel_url}#sha256={sha256(wheel_path)}">'
                f"{wheel_path.name}</a>"
                "</body></html>\n"
            ),
            encoding="utf-8",
        )

    requirements_lock = (
        f"psb-leaf==1.0.0 --hash=sha256:{sha256(leaf_wheel)}\n"
        f"psb-parent==1.0.0 --hash=sha256:{sha256(parent_wheel)}\n"
    )
    (python_directory / "requirements.lock").write_text(
        requirements_lock,
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
