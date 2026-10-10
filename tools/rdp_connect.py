#!/usr/bin/env python3
"""rdp_connect.py - self-healing Remote Desktop launcher.

Never shows a cryptic Win32 dialog. Flow:

  1. Silent preflight of the inbox RDP chain (rdclientax.dll, mstsc.exe).
  2. Healthy   -> launch mstsc.exe (optionally with an .rdp file), report OK.
  3. Broken    -> check for the standalone Store client (independent of the
                  inbox ActiveX chain); if present, open it for the user.
  4. Otherwise -> print ONE structured report with the single guided fix
                  (elevated DISM/SFC), exit code 1. No tracebacks, no popups.

Usage:
    python tools/rdp_connect.py [--rdp-file session.rdp] [--check-only] [--dry-run]

Exit codes: 0 executed/healthy, 1 blocked (guidance printed), 2 usage error.
"""

import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "lib"))
from selfheal import (  # noqa: E402
    EXIT_BLOCKED, EXIT_OK, EXIT_USAGE,
    CommandCheck, FileCheck, HealthReport, RegistryCheck, Router,
)

SYSTEM32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                        "System32")
RDCLIENTAX = os.path.join(SYSTEM32, "rdclientax.dll")
MSTSC = os.path.join(SYSTEM32, "mstsc.exe")

REPAIR_GUIDE = """\
Run these three commands in ONE Administrator terminal
(right-click terminal -> Run as administrator), then reboot:

    DISM /Online /Cleanup-Image /RestoreHealth
    sfc /scannow
    dir C:\\Windows\\System32\\rdclientax.dll   (must list the file)

Until then, use Microsoft Remote Desktop from the Microsoft Store -
open the Store app, search "Microsoft Remote Desktop", install it,
and connect through it. It does not use rdclientax.dll."""


def store_client_present():
    """True if the standalone Store Remote Desktop client is installed."""
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-AppxPackage -Name '*RemoteDesktop*' | "
             "Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return bool(p.stdout and p.stdout.strip())


def open_store_client():
    """Open the Microsoft Store app so the user can install the client."""
    try:
        os.startfile("ms-windows-store:")
        return True
    except OSError as exc:
        return ("Could not open the Store app (%s). Open it manually and "
                "search 'Microsoft Remote Desktop'." % exc)


def launch_mstsc(rdp_file):
    """Launch the native client. Only called when preflight is HEALTHY."""
    cmd = [MSTSC] + ([rdp_file] if rdp_file else [])
    try:
        subprocess.Popen(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            creationflags=getattr(subprocess, "DETACHED_PROCESS", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))
    except OSError as exc:
        return ("Native launch failed at the last step (%s). Fall through "
                "to the guided fix below.\n%s" % (exc, REPAIR_GUIDE))
    return True


def build_report():
    report = HealthReport("RDP launch chain")
    report.add(FileCheck(
        "ActiveX control rdclientax.dll", RDCLIENTAX,
        hint="File is missing from System32. " + REPAIR_GUIDE.split("\n")[0]))
    report.add(CommandCheck(
        "Native client mstsc.exe", [MSTSC],
        hint="mstsc.exe itself is missing - mailbox Windows install; "
             "run the repair guide, then retry."))
    report.add(RegistryCheck(
        "Terminal Server Client registration", "HKEY_LOCAL_MACHINE",
        r"SOFTWARE\Microsoft\Terminal Server Client",
        hint="Registration hive absent - same repair guide applies."))
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--rdp-file", default="",
                    help="optional .rdp session file to open")
    ap.add_argument("--check-only", action="store_true",
                    help="print the health report and exit (launch nothing)")
    ap.add_argument("--dry-run", action="store_true",
                    help="show the routing decision without launching")
    args = ap.parse_args(argv)

    if args.rdp_file and not os.path.isfile(args.rdp_file):
        print("[-] unknown --rdp-file: %s" % args.rdp_file)
        return EXIT_USAGE

    report = build_report()
    report.render()

    if args.check_only:
        return EXIT_OK if report.ok() else EXIT_BLOCKED

    router = Router()
    if report.ok():
        if args.dry_run:
            print("[*] routing: HEALTHY -> would launch: %s"
                  % " ".join([MSTSC] + ([args.rdp_file]
                                        if args.rdp_file else [])))
            return EXIT_OK
        outcome = launch_mstsc(args.rdp_file or "")
        if outcome is True:
            print("[+] native RDP client launched.")
            return EXIT_OK
        print(outcome)
        return EXIT_BLOCKED

    # --- Broken chain: never launch mstsc (that is what spawns the raw
    # --- dialogs). Route to fallbacks instead.
    print("[*] routing: inbox chain BROKEN -> mstsc launch suppressed "
          "(no cryptic dialogs will appear).")

    def try_store_client():
        if not store_client_present():
            return ("Standalone Store client is not installed.\n"
                    + REPAIR_GUIDE)
        if args.dry_run:
            return True  # would open it; show decision only
        return open_store_client()

    router.add("standalone Store client", try_store_client)
    if router.run():
        if not args.dry_run:
            print("[+] opened an RDP path that does not need rdclientax.dll.")
        return EXIT_OK

    print()
    print("=" * 68)
    print("  Single guided fix (copy-paste as Administrator):")
    print("=" * 68)
    print(REPAIR_GUIDE)
    return EXIT_BLOCKED


if __name__ == "__main__":
    sys.exit(main())
