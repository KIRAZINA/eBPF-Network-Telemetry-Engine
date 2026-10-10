#!/usr/bin/env python3
"""engine_manager.py - smart bootstrap and environment diagnostic utility.

Detects native Linux vs. Windows+WSL2, translates paths, and orchestrates the
full build pipeline (CMake configure -> parallel build -> CTest) inside the
correct target environment. Standard library only.

Usage (Windows, from the repo root):
    python engine_manager.py
    python engine_manager.py --asan --jobs 8
    python engine_manager.py --dry-run        # print the plan, run nothing

Usage (native Linux, from the repo root):
    python3 engine_manager.py
"""

import argparse
import os
import platform
import shlex
import shutil
import subprocess
import sys
from typing import NoReturn

OK, FAIL, INFO = "[+]", "[-]", "[*]"
CMAKE_MIN = (3, 22)


def header(title: str) -> None:
    print()
    print("=" * 68)
    print("  %s" % title)
    print("=" * 68)


def run_capture(argv: list, *, cwd: str | None = None) -> tuple:
    """Run argv, capturing output. Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(argv, capture_output=True, text=True,
                           cwd=cwd, timeout=120)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except FileNotFoundError:
        return 127, "", "command not found: %s" % argv[0]
    except subprocess.TimeoutExpired:
        return 124, "", "timed out: %s" % " ".join(argv)


def run_stream(argv: list) -> int:
    """Run argv with inherited stdio so build output streams live."""
    try:
        return subprocess.run(argv).returncode
    except FileNotFoundError:
        print("%s command not found: %s" % (FAIL, argv[0]))
        return 127


def decode_cli(data: bytes) -> str:
    """Decode a child capture. wsl.exe emits UTF-16; anything else is locale."""
    if b"\x00" in data:
        try:
            return data.decode("utf-16")
        except UnicodeDecodeError:
            return data.decode("utf-16-le", errors="replace")
    enc = sys.stdout.encoding or "utf-8"
    return data.decode(enc, errors="replace")


def run_bytes(argv: list, *, cwd: str | None = None) -> tuple:
    """Run argv, returning (rc, stdout_bytes, stderr_bytes)."""
    try:
        p = subprocess.run(argv, capture_output=True, cwd=cwd, timeout=120)
        return p.returncode, p.stdout or b"", p.stderr or b""
    except FileNotFoundError:
        return 127, b"", b"command not found: %s" % argv[0]
    except subprocess.TimeoutExpired:
        return 124, b"", b"timed out"


def die(msg: str, hint: str = "") -> NoReturn:
    print("%s %s" % (FAIL, msg))
    if hint:
        print("    -> %s" % hint)
    sys.exit(1)


# --------------------------------------------------------------------------
# 1. Environment detection
# --------------------------------------------------------------------------

def check_wsl() -> list:
    """Validate WSL2 + at least one installed distro. Returns distro names."""
    if shutil.which("wsl") is None:
        die("WSL launcher (wsl.exe) not found on PATH.",
            "Install WSL2: run `wsl --install` in an elevated PowerShell, "
            "reboot, then re-run this script.")
    rc, out, err = run_capture(["wsl", "--status"])
    if rc != 0:
        die("`wsl --status` failed: %s" % (err or out or "unknown error"),
            "Install/enable WSL2 with `wsl --install` (elevated PowerShell), "
            "reboot, and ensure virtualization is enabled in BIOS/UEFI.")
    print("%s WSL status OK" % OK)

    rc, out_b, err_b = run_bytes(["wsl", "-l", "-q"])
    out, err = decode_cli(out_b), decode_cli(err_b)
    distros = [l.strip() for l in out.splitlines() if l.strip()]
    if rc != 0 or not distros:
        die("No WSL Linux distributions installed.",
            "Install one, e.g. `wsl --install -d Ubuntu`, launch it once to "
            "complete setup, then re-run this script.")
    print("%s WSL distro(s): %s" % (OK, ", ".join(distros)))
    return distros


def detect_environment() -> tuple:
    """Returns (mode, detail) with mode 'linux' or 'wsl'."""
    system = platform.system()
    if system == "Linux":
        print("%s native Linux detected (%s)" % (OK, platform.release()))
        return "linux", ""
    if system == "Windows":
        print("%s Windows host detected - targeting WSL2" % INFO)
        distros = check_wsl()
        return "wsl", distros[0]
    die("Unsupported host OS: %s (need Linux or Windows+WSL2)." % system)


def translate_path(dry_run: bool) -> str:
    """Translate the Windows CWD to its WSL path via `wsl wslpath -u .`."""
    rc, out, err = run_capture(["wsl", "wslpath", "-a", "-u", "."])
    if rc != 0 or not out:
        if dry_run:
            return "<wsl-path-of-repo>"
        die("Path translation failed: %s" % (err or "empty output"),
            "Ensure the repo lives on a WSL-accessible drive (e.g. C:) and "
            "your default distro is functional (`wsl -l -v`).")
    out = out.rstrip("/") or "/"
    print("%s repo WSL path: %s" % (OK, out))
    return out


# --------------------------------------------------------------------------
# 2. Preflight + orchestration
# --------------------------------------------------------------------------

def preflight(sh: callable, dry_run: bool) -> None:
    """Check cmake + compiler inside the target environment (BTF: warn only)."""
    header("Preflight - target environment tooling")
    if dry_run:
        print("%s [dry-run] would check: cmake --version, compiler, BTF" % INFO)
        return
    # NOTE: gates must be pipe-free — a pipeline's exit status is its LAST
    # stage (e.g. `cmake --version | head` succeeds even when cmake is absent).
    for probe in ("command -v cmake",
                  "command -v g++ || command -v clang++"):
        rc = sh(probe)
        if rc != 0:
            die("Preflight failed: `%s` (exit %d)" % (probe, rc),
                "Install the toolchain in the target env - Debian/Ubuntu: "
                "`sudo apt install build-essential cmake ninja-build clang "
                "libbpf-dev libelf-dev zlib1g-dev bpftool`; "
                "RHEL/Fedora: `sudo dnf install gcc-c++ cmake ninja-build "
                "clang libbpf-devel elfutils-libelf-devel zlib-devel bpftool`.")
    print("%s toolchain OK" % OK)
    # BTF is optional at build time (stub fallback) - warn, don't fail.
    if sh("test -e /sys/kernel/btf/vmlinux") != 0:
        print("%s no /sys/kernel/btf/vmlinux in target - vmlinux.h will use "
              "the stub fallback; generate it on a BTF host for production "
              "loads (see Deployment-Runbook §5.2)." % INFO)
    else:
        print("%s kernel BTF present" % OK)


def build_plan(repo: str, args) -> tuple:
    """Returns (build_dir, configure_cmd, build_cmd, test_cmd) for bash -lc."""
    build_dir = args.build_dir
    if args.asan:
        build_dir = args.build_dir + "-asan"
        build_type = "Debug"
        asan_flag = " -DENABLE_ASAN=ON"
    else:
        build_type = "Release"
        asan_flag = ""
    q = shlex.quote(repo)
    configure = ("cmake -S %s -B %s -DCMAKE_BUILD_TYPE=%s%s" %
                 (q, build_dir, build_type, asan_flag))
    build = "cmake --build %s -j%d" % (build_dir, args.jobs)
    test = ("ctest --test-dir %s --output-on-failure" % build_dir)
    return build_dir, configure, build, test


def phase(name: str, cmd: str, sh: callable, dry_run: bool) -> None:
    header(name)
    print("%s $ %s" % (INFO, cmd))
    if dry_run:
        print("%s [dry-run] skipped" % INFO)
        return
    if sh(cmd) != 0:
        die("Phase failed: %s" % name,
            "Re-run the echoed command above inside the target environment.")
    print("%s %s - OK" % (OK, name))


def print_next_steps(repo: str, mode: str, build_dir: str) -> None:
    header("Done - run the daemon")
    if mode == "wsl":
        exe = "%s/%s/bin/ebpf-telemetry-daemon" % (repo, build_dir)
        obj = "%s/%s/src/kernel/telemetry.bpf.o" % (repo, build_dir)
        print("Copy-paste inside WSL (root required for BPF load + XDP):")
        print()
        print("  IFINDEX=$(ip -o link show eth0 | awk -F': ' '{print $1}')")
        print("  sudo %s %s \"$IFINDEX\" 9090" % (exe, obj))
        print()
        print("Or one-shot from Windows PowerShell:")
        print()
        print("  wsl sudo %s %s $(wsl ip -o link show eth0 | awk -F': ' '{print $1}') 9090"
              % (exe, obj))
        print()
        print("Then verify:  curl -s http://localhost:9090/healthz")
    else:
        print("Copy-paste (root required for BPF load + XDP):")
        print()
        print("  IFINDEX=$(ip -o link show eth0 | awk -F': ' '{print $1}')")
        print("  sudo ./%s/bin/ebpf-telemetry-daemon "
              "./%s/src/kernel/telemetry.bpf.o \"$IFINDEX\" 9090" % (build_dir, build_dir))
    print()
    print("Synthetic traffic check:")
    print("  sudo python3 contrib/synth_traffic.py --target 127.0.0.1 "
          "--syn-count 200 --ports 80,443,8000-8010")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--asan", action="store_true",
                    help="Debug + -DENABLE_ASAN=ON build (staging/QA)")
    ap.add_argument("--jobs", type=int, default=0,
                    help="parallel build jobs (default: nproc)")
    ap.add_argument("--build-dir", default="build",
                    help="build directory name (default: build)")
    ap.add_argument("--skip-tests", action="store_true",
                    help="skip the ctest phase")
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan without executing anything")
    args = ap.parse_args()

    header("engine_manager - bootstrap + diagnostics")
    print("%s host: %s %s | python %s" %
          (INFO, platform.system(), platform.release(),
           platform.python_version()))

    mode, _ = detect_environment()

    if mode == "wsl":
        repo = translate_path(args.dry_run)
        qr = shlex.quote(repo)
        sh = lambda cmd: run_stream(  # noqa: E731 - tiny runner closure
            ["wsl", "bash", "-lc", "cd %s && %s" % (qr, cmd)])

        if args.jobs <= 0:
            rc, out, _ = run_capture(["wsl", "bash", "-lc", "nproc"])
            args.jobs = int(out) if rc == 0 and out.isdigit() else 4
    else:
        repo = os.getcwd()
        print("%s repo path: %s" % (OK, repo))
        sh = lambda cmd: run_stream(["bash", "-lc", cmd])  # noqa: E731

        if args.jobs <= 0:
            args.jobs = os.cpu_count() or 4

    print("%s build jobs: %d" % (INFO, args.jobs))
    preflight(sh, args.dry_run)
    build_dir, configure, build_cmd, test_cmd = build_plan(repo, args)

    phase("Phase 1 - CMake configure (%s)" %
          ("Debug+ASan" if args.asan else "Release"), configure, sh,
          args.dry_run)
    phase("Phase 2 - Parallel compile (-j%d)" % args.jobs, build_cmd, sh,
          args.dry_run)
    if args.skip_tests:
        print("%s ctest skipped (--skip-tests)" % INFO)
    else:
        phase("Phase 3 - CTest (incl. [stress]/[perf] gates)", test_cmd, sh,
              args.dry_run)

    print_next_steps(repo if mode == "wsl" else ".", mode, build_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
