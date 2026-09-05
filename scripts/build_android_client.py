#!/usr/bin/env python3
"""Build the bundled Android DEX helper from source using javac and Android d8."""
import argparse
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def find_d8():
    configured = os.getenv("D8")
    if configured:
        return configured
    installed = shutil.which("d8")
    if installed:
        return installed
    roots = [Path(value).expanduser() for key in ("ANDROID_HOME", "ANDROID_SDK_ROOT")
             if (value := os.getenv(key))]
    roots.extend([Path.home() / "Library/Android/sdk", Path.home() / "Android/Sdk",
                  Path("/opt/homebrew/share/android-commandlinetools"),
                  Path("/usr/local/share/android-commandlinetools")])
    for root in roots:
        candidates = list((root / "build-tools").glob("*/d8"))
        candidates.sort(key=lambda p: tuple(int(n) for n in re.findall(r"\d+", p.parent.name)), reverse=True)
        if candidates:
            return str(candidates[0])
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--d8", default=find_d8(), help="Path to Android SDK Build-Tools d8")
    parser.add_argument("--javac", default=os.getenv("JAVAC", "javac"))
    args = parser.parse_args()
    if not args.d8:
        parser.error("Install Android SDK Build-Tools or supply --d8 /path/to/d8")
    project = Path(__file__).resolve().parent.parent
    build_root = project / "work"
    build_root.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="android-build-", dir=build_root) as temporary:
        build = Path(temporary)
        subprocess.run([args.javac, "--release", "8", "-Xlint:-options", "-d", str(build),
                        str(project / "android/SuearUsbClient.java")], check=True)
        jar = build / "suear-usb-client.jar"
        subprocess.run([args.d8, "--min-api", "26", "--output", str(jar),
                        str(build / "SuearUsbClient.class")], check=True)
        shutil.copyfile(jar, project / "suear-usb-client.jar")
    print("Built suear-usb-client.jar from android/SuearUsbClient.java")


if __name__ == "__main__":
    main()
