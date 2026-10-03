#!/usr/bin/env python3
"""
Release and Version Management Utility.

Automates version bumping, sanity checking, and release tagging for openappa-antigravity:
  python scripts/release.py --current
  python scripts/release.py --bump patch
  python scripts/release.py --bump minor
  python scripts/release.py 0.2.0 --tag --push
"""

from __future__ import annotations
import argparse
import re
import subprocess
import sys
from pathlib import Path
from typing import Tuple

ROOT_DIR = Path(__file__).resolve().parent.parent

VERSION_FILES = [
    ROOT_DIR / "pyproject.toml",
    ROOT_DIR / "appa-package.toml",
    ROOT_DIR / "runtime" / "__init__.py",
    ROOT_DIR / "adapter" / "__init__.py",
]


def get_current_version() -> str:
    pyproject = (ROOT_DIR / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'version\s*=\s*"([^"]+)"', pyproject)
    if not m:
        raise ValueError("Could not find version in pyproject.toml")
    return m.group(1)


def parse_semver(v: str) -> Tuple[int, int, int]:
    parts = v.strip().split(".")
    if len(parts) != 3:
        raise ValueError(f"Version '{v}' is not valid semantic version (X.Y.Z)")
    return int(parts[0]), int(parts[1]), int(parts[2])


def bump_version(current: str, part: str) -> str:
    major, minor, patch = parse_semver(current)
    if part == "major":
        return f"{major + 1}.0.0"
    elif part == "minor":
        return f"{major}.{minor + 1}.0"
    elif part == "patch":
        return f"{major}.{minor}.{patch + 1}"
    raise ValueError(f"Unknown bump part: {part}")


def update_version_files(new_ver: str) -> None:
    # 1. pyproject.toml
    pyproject_path = ROOT_DIR / "pyproject.toml"
    content = pyproject_path.read_text(encoding="utf-8")
    content = re.sub(r'version\s*=\s*"[^"]+"', f'version = "{new_ver}"', content, count=1)
    pyproject_path.write_text(content, encoding="utf-8")

    # 2. appa-package.toml
    appa_pkg_path = ROOT_DIR / "appa-package.toml"
    if appa_pkg_path.exists():
        content = appa_pkg_path.read_text(encoding="utf-8")
        content = re.sub(r'version\s*=\s*"[^"]+"', f'version = "{new_ver}"', content, count=1)
        appa_pkg_path.write_text(content, encoding="utf-8")

    # 3. runtime/__init__.py
    rt_init = ROOT_DIR / "runtime" / "__init__.py"
    if rt_init.exists():
        rt_init.write_text(f'"""\nOpenAPPA Runtime package.\n"""\n\n__version__ = "{new_ver}"\n', encoding="utf-8")

    # 4. adapter/__init__.py
    ad_init = ROOT_DIR / "adapter" / "__init__.py"
    if ad_init.exists():
        ad_init.write_text(f'"""\nOpenAPPA Antigravity Adapter package.\n"""\n\n__version__ = "{new_ver}"\n', encoding="utf-8")

    # 5. README.md badge
    readme_path = ROOT_DIR / "README.md"
    if readme_path.exists():
        content = readme_path.read_text(encoding="utf-8")
        content = re.sub(r'version-[\d\.]+-informational', f'version-{new_ver}-informational', content, count=1)
        readme_path.write_text(content, encoding="utf-8")


def run_checks() -> bool:
    print("[Release] Running pre-release verification...")
    # describe --check
    r1 = subprocess.run([sys.executable, "appa.py", "describe", "--check"], cwd=ROOT_DIR)
    if r1.returncode != 0:
        print("[ERROR] Policy check failed!", file=sys.stderr)
        return False

    # replay
    r2 = subprocess.run([sys.executable, "appa.py", "replay", "policy-tests/"], cwd=ROOT_DIR)
    if r2.returncode != 0:
        print("[ERROR] Replay tests failed!", file=sys.stderr)
        return False

    # unittest
    r3 = subprocess.run([sys.executable, "-m", "unittest", "tests/test_suite.py"], cwd=ROOT_DIR)
    if r3.returncode != 0:
        print("[ERROR] Unit tests failed!", file=sys.stderr)
        return False

    print("[Release] All pre-release verification checks PASSED.")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage openappa-antigravity versioning and releases")
    parser.add_argument("version", nargs="?", help="Explicit new version (e.g. 0.2.0)")
    parser.add_argument("--current", action="store_true", help="Print current version and exit")
    parser.add_argument("--bump", choices=["patch", "minor", "major"], help="Bump semantic version part")
    parser.add_argument("--tag", action="store_true", help="Create git tag (e.g. v0.1.0)")
    parser.add_argument("--push", action="store_true", help="Push commit and tag to git remote")
    parser.add_argument("--skip-checks", action="store_true", help="Skip pre-release tests")

    args = parser.parse_args()

    curr = get_current_version()
    if args.current:
        print(f"Current version: {curr}")
        return

    if args.bump:
        target_version = bump_version(curr, args.bump)
    elif args.version:
        target_version = args.version
    else:
        parser.print_help()
        return

    print(f"[Release] Upgrading version: {curr} -> {target_version}")

    if not args.skip_checks:
        if not run_checks():
            sys.exit(1)

    update_version_files(target_version)
    print(f"[Release] Updated version to {target_version} in all package manifests.")

    if args.tag or args.push:
        # Commit updated files
        msg = f"Release v{target_version}"
        subprocess.run(["git", "add", "-A"], cwd=ROOT_DIR, check=True)
        subprocess.run(["git", "commit", "-m", msg], cwd=ROOT_DIR, check=False)
        tag_name = f"v{target_version}"
        subprocess.run(["git", "tag", "-a", tag_name, "-m", msg], cwd=ROOT_DIR, check=True)
        print(f"[Release] Created git tag {tag_name}")

        if args.push:
            subprocess.run(["git", "push", "origin", "main"], cwd=ROOT_DIR, check=True)
            subprocess.run(["git", "push", "origin", tag_name], cwd=ROOT_DIR, check=True)
            print(f"[Release] Pushed main and tag {tag_name} to origin!")


if __name__ == "__main__":
    main()
