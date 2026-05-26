#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path


VERSIONS_URL = "https://julialang-s3.julialang.org/bin/versions.json"


def run(cmd):
    print("+", " ".join(map(str, cmd)), flush=True)
    subprocess.run(cmd, check=True)


def version_tuple(version):
    return tuple(int(part) for part in version.split("."))


def download(url, dest):
    run(["curl", "--fail", "--location", "--retry", "3", "--output", dest, url])


def select_version(versions, spec):
    stable = [version for version in versions if "-" not in version]
    if spec == "1":
        candidates = stable
    else:
        prefix = spec + "."
        candidates = [version for version in stable if version.startswith(prefix)]
    if not candidates:
        raise SystemExit(f"no Julia versions match {spec!r}")
    return max(candidates, key=version_tuple)


def select_file(version_info, runner_os, arch):
    os_map = {
        "Linux": "linux",
        "macOS": "mac",
        "Windows": "winnt",
    }
    arch_map = {
        "x64": "x86_64",
        "x86": "i686",
        "aarch64": "aarch64",
    }
    target_os = os_map[runner_os]
    target_arch = arch_map[arch]
    target_ext = "zip" if target_os == "winnt" else "tar.gz"
    for file in version_info["files"]:
        if (
            file.get("kind") == "archive"
            and file.get("os") == target_os
            and file.get("arch") == target_arch
            and file.get("extension") == target_ext
        ):
            return file
    raise SystemExit(f"no Julia archive for os={target_os}, arch={target_arch}")


def extract(archive, dest):
    if archive.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            zf.extractall(dest)
    else:
        with tarfile.open(archive) as tf:
            tf.extractall(dest)


def find_bindir(root):
    exe = "julia.exe" if os.name == "nt" else "julia"
    for path in Path(root).rglob(exe):
        if path.parent.name == "bin":
            return path.parent
    raise SystemExit("could not find extracted Julia binary")


def main():
    if len(sys.argv) != 4:
        raise SystemExit("usage: install-julia.py <version-spec> <runner-os> <arch>")
    spec, runner_os, arch = sys.argv[1:]
    with tempfile.TemporaryDirectory() as tmp:
        versions_path = os.path.join(tmp, "versions.json")
        download(VERSIONS_URL, versions_path)
        versions = json.loads(Path(versions_path).read_text())
        version = select_version(versions, spec)
        file = select_file(versions[version], runner_os, arch)
        archive = os.path.join(tmp, os.path.basename(file["url"]))
        print(f"Installing Julia {version} for {runner_os} {arch}", flush=True)
        download(file["url"], archive)
        install_root = Path(os.environ.get("RUNNER_TEMP", tmp)) / f"julia-{version}-{arch}"
        if install_root.exists():
            shutil.rmtree(install_root)
        install_root.mkdir(parents=True)
        extract(archive, install_root)
        bindir = find_bindir(install_root)
        github_path = os.environ.get("GITHUB_PATH")
        if github_path:
            with open(github_path, "a", encoding="utf-8") as io:
                print(bindir, file=io)
        print(f"Julia bin directory: {bindir}", flush=True)


if __name__ == "__main__":
    main()
