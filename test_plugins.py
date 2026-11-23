#!/usr/bin/env python3
"""Validation and Orochi compatibility test suite for orochi_plugins."""

import argparse
import concurrent.futures
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

VALID_OS = {"", "Linux", "Windows", "Mac"}


def validate_catalog(check_urls: bool = False) -> list[str]:
    errors: list[str] = []
    with open("data.json", "r", encoding="utf-8") as f:
        payload = json.load(f)

    rows = payload.get("data")
    if not isinstance(rows, list) or not rows:
        return ["data.json must contain a non-empty 'data' list"]

    zips_in_json = set()
    for i, row in enumerate(rows):
        if not isinstance(row, list) or len(row) != 6:
            errors.append(f"Row {i}: expected 6 elements, got {row!r}")
            continue
        author, plugin, url, zipf, _, os_name = row
        if not author or not plugin or not url:
            errors.append(f"Row {i}: missing required field {row!r}")
        if os_name not in VALID_OS:
            errors.append(f"Row {i}: invalid OS {os_name!r}")
        if zipf:
            zips_in_json.add(zipf)
            if not os.path.exists(zipf):
                errors.append(f"Row {i}: referenced zip not found: {zipf}")

    zips_on_disk = set(glob.glob("*.zip"))
    for extra in sorted(zips_on_disk - zips_in_json):
        errors.append(f"Unreferenced zip file on disk: {extra}")

    # Validate Orochi flat zip structure
    for z in sorted(zips_on_disk):
        with zipfile.ZipFile(z, "r") as zf:
            names = zf.namelist()
            if not any(n.endswith(".py") for n in names):
                errors.append(f"{z}: contains no .py files")
            for n in names:
                if "/" in n or "\\" in n:
                    errors.append(f"{z}: nested path not supported by Orochi plugin_install.py: {n}")

    if check_urls:
        def _head(row):
            author, plugin, url = row[0], row[1], row[2]
            req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "orochi-plugins-test"})
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    return (r.status, author, plugin, url)
            except urllib.error.HTTPError as e:
                return (e.code, author, plugin, url)
            except Exception as e:
                return (str(e), author, plugin, url)

        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
            for status, author, plugin, url in ex.map(_head, rows):
                if status != 200:
                    errors.append(f"URL check failed ({status}): {author} / {plugin} -> {url}")

    print(f"Catalog: {len(rows)} plugins, {len(zips_on_disk)} zip packages")
    return errors


def test_volatility_load(vol_python: str, install_deps: bool = False) -> list[str]:
    errors: list[str] = []
    py = Path(vol_python)
    vol_plugins = Path(
        subprocess.check_output(
            [str(py), "-c", "import volatility3.plugins, pathlib; print(pathlib.Path(volatility3.plugins.__file__).parent)"],
            text=True,
        ).strip()
    )
    custom_dir = vol_plugins / "custom"

    zips = sorted(glob.glob("*.zip"))
    print(f"\nTesting {len(zips)} zip packages against {py} ({vol_plugins}):")

    for z in zips:
        if custom_dir.exists():
            shutil.rmtree(custom_dir)
        custom_dir.mkdir(parents=True)
        (custom_dir / "__init__.py").write_text("", encoding="utf-8")

        py_names = []
        has_sh = False
        deps_status = "none"
        deps_failed = False

        with zipfile.ZipFile(z, "r") as zf, tempfile.TemporaryDirectory() as td:
            names = zf.namelist()
            has_sh = any(n.endswith(".sh") for n in names)
            for name in names:
                if name.endswith(".sh"):
                    continue
                elif name.lower() == "requirements.txt":
                    if install_deps:
                        req_file = Path(td) / "requirements.txt"
                        req_file.write_bytes(zf.read(name))
                        cmd = (
                            ["uv", "pip", "install", "--python", str(py), "-r", str(req_file)]
                            if shutil.which("uv")
                            else [str(py), "-m", "pip", "install", "-r", str(req_file)]
                        )
                        p = subprocess.run(cmd, capture_output=True, text=True)
                        if p.returncode != 0:
                            deps_failed = True
                            deps_status = "FAIL"
                            tail = " | ".join((p.stderr or p.stdout).strip().splitlines()[-2:])
                            if has_sh:
                                print(f"  WARN  {z:28s} | deps require system packages (.sh): {tail}")
                            else:
                                errors.append(f"{z}: dependency install failed: {tail}")
                                print(f"  FAIL  {z:28s} | deps failed: {tail}")
                        else:
                            deps_status = "ok"
                    else:
                        deps_status = "skipped"
                elif name.endswith(".py"):
                    (custom_dir / name).write_bytes(zf.read(name))
                    py_names.append(Path(name).stem)

        if deps_failed:
            continue

        check_code = f"""
import importlib, volatility3.plugins
from volatility3 import framework
from volatility3.framework import contexts

_ = contexts.Context()
framework.import_files(volatility3.plugins, True)
found, req_errors = [], []
for name, cls in framework.list_plugins().items():
    for py_name in {py_names!r}:
        if name.startswith(f"custom.{{py_name}}"):
            try:
                reqs = cls.get_requirements()
                found.append(f"{{name}} ({{len(reqs)}} reqs)")
            except Exception as e:
                req_errors.append(f"{{name}}: {{type(e).__name__}}: {{e}}")
if req_errors:
    print("REQ_ERRORS:", "; ".join(req_errors))
if found:
    print("FOUND:", ", ".join(found))
else:
    for py_name in {py_names!r}:
        try:
            importlib.import_module(f"volatility3.plugins.custom.{{py_name}}")
        except Exception as e:
            print(f"IMPORT_ERR ({{py_name}}): {{type(e).__name__}}: {{e}}")
"""
        p = subprocess.run([str(py), "-c", check_code], capture_output=True, text=True)
        out = (p.stdout + "\n" + p.stderr).strip()
        if "FOUND:" in out and "REQ_ERRORS:" not in out:
            found_line = [l for l in out.splitlines() if l.startswith("FOUND:")][0]
            note = " (needs .sh)" if has_sh else ""
            print(f"  OK    {z:28s} | deps={deps_status:7s} | {found_line}{note}")
        elif has_sh and "ModuleNotFoundError" in out:
            print(f"  WARN  {z:28s} | deps require system packages (.sh) -> skipped load")
        else:
            tail = " | ".join(out.splitlines()[-2:])
            errors.append(f"{z}: load failed: {tail}")
            print(f"  FAIL  {z:28s} | deps={deps_status:7s} | {tail}")

    if custom_dir.exists():
        shutil.rmtree(custom_dir)

    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate orochi_plugins catalog and zip packages.")
    parser.add_argument("--check-urls", action="store_true", help="Verify HTTP 200 for all plugin URLs.")
    parser.add_argument("--vol-python", help="Path to a Python interpreter with volatility3 installed.")
    parser.add_argument("--install-deps", action="store_true", help="Install each zip's requirements.txt before loading.")
    args = parser.parse_args()

    errors = validate_catalog(check_urls=args.check_urls)
    if args.vol_python:
        errors.extend(test_volatility_load(args.vol_python, install_deps=args.install_deps))

    if errors:
        print("\nFAILED:")
        for err in errors:
            print(" -", err)
        return 1

    print("\nALL CHECKS PASSED!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
