"""Build Windows desktop + CLI, a portable ZIP and SHA-256 checksums."""
import hashlib
import argparse
import platform
import subprocess
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from xss_audit import __version__


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package-only", action="store_true", help="Refresh ZIP and checksums for already built executables")
    args = parser.parse_args()
    if sys.platform != "win32" or platform.machine().lower() not in {"amd64", "x86_64"}:
        raise SystemExit("Build these Windows x64 artifacts on Windows x64.")
    output = ROOT / "release" / f"v{__version__}"
    output.mkdir(parents=True, exist_ok=True)
    entries = [] if args.package_only else [("desktop.py", "XSS-Audit-Desktop", True), ("cli.py", "xss-audit-cli", False)]
    for entry, name, windowed in entries:
        command = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", "--onefile",
                   "--name", name, "--distpath", str(output), "--workpath", str(ROOT / "build" / name),
                   "--specpath", str(ROOT / "build"),
                   "--add-data", str(ROOT / "xss_audit" / "audit-playbook.md") + ";xss_audit",
                   "--add-data", str(ROOT / "xss_audit" / "UPSTREAM-LICENSE.txt") + ";xss_audit",
                   "--add-data", str(ROOT / "THIRD-PARTY-NOTICES.txt") + ";xss_audit",
                   "--collect-all", "tree_sitter", "--collect-all", "tree_sitter_javascript", "--collect-all", "tree_sitter_typescript"]
        if windowed:
            command.append("--windowed")
        command.append(str(ROOT / entry))
        print("Building " + name, flush=True)
        with (ROOT / "build" / f"{name}.log").open("w", encoding="utf-8") as log:
            subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=True)
    bundle = output / f"XSS-Audit-v{__version__}-windows-x64.zip"
    assets = [output / "XSS-Audit-Desktop.exe", output / "xss-audit-cli.exe"]
    if not all(path.is_file() for path in assets):
        raise SystemExit("Build both executables before packaging.")
    version = subprocess.check_output([str(assets[1]), "--version"], encoding="utf-8").strip()
    if version != __version__:
        raise SystemExit("Executable version does not match source version.")
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in assets:
            archive.write(path, path.name)
        for name in ["README.md", "LICENSE", "NOTICE.md", "SKILL.md", "THIRD-PARTY-NOTICES.txt"]:
            archive.write(ROOT / name, name)
        for path in (ROOT / "examples" / "demo-project").rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(ROOT).as_posix())
        archive.write(ROOT / "examples" / "demo-report.html", "examples/demo-report.html")
    assets.append(bundle)
    checksums = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}" for path in assets]
    (output / "SHA256SUMS.txt").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    print("Release ready: " + str(output), flush=True)


if __name__ == "__main__":
    (ROOT / "build").mkdir(exist_ok=True)
    main()
