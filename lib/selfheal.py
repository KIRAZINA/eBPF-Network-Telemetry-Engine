"""selfheal.py - universal pre-execution diagnostics + fallback routing.

A tiny, dependency-free framework for self-healing launchers. Pattern:

    from selfheal import Check, FileCheck, CommandCheck, HealthReport, Router

    report = HealthReport("RDP chain")
    report.add(FileCheck("ActiveX control", path, hint="..."))
    report.add(CommandCheck("client binary", ["mstsc.exe", "/?"]))
    if not report.ok():
        report.render()          # structured, human-readable, no tracebacks
        Router([...fallbacks]).run()   # first working alternative wins
        raise SystemExit(report.exit_code)

Design rules enforced here:
  * Checks never raise. A crashing check reports itself as failed with the
    exception text captured (zero stack traces reach the user).
  * Nothing prints raw Win32/system error text. Every failure carries a
    human-written hint with the single next step.
  * ASCII-only output (safe on legacy console code pages).
  * Exit codes are part of the contract: 0 = executed/healthy,
    1 = blocked but guidance printed, 2 = usage error.
"""

import os
import shutil
import subprocess
import sys

EXIT_OK = 0
EXIT_BLOCKED = 1
EXIT_USAGE = 2


class CheckResult:
    """Outcome of one health check (never an exception)."""

    def __init__(self, name, ok, detail="", hint=""):
        self.name = name
        self.ok = ok
        self.detail = detail
        self.hint = hint


class Check:
    """Base check: subclasses implement probe() -> (ok, detail)."""

    def __init__(self, name, hint=""):
        self.name = name
        self.hint = hint

    def probe(self):
        raise NotImplementedError

    def run(self):
        try:
            ok, detail = self.probe()
            return CheckResult(self.name, bool(ok), str(detail or ""),
                               "" if ok else self.hint)
        except Exception as exc:  # noqa: BLE001 - captured, never raised
            return CheckResult(self.name, False,
                               "check crashed: %s: %s"
                               % (type(exc).__name__, exc), self.hint)


class FileCheck(Check):
    """Required file must exist (and be non-empty)."""

    def __init__(self, name, path, hint=""):
        super().__init__(name, hint)
        self.path = path

    def probe(self):
        if os.path.isfile(self.path) and os.path.getsize(self.path) > 0:
            return True, self.path
        return False, "missing: %s" % self.path


class CommandCheck(Check):
    """Required command must resolve on PATH (and optionally run cleanly)."""

    def __init__(self, name, argv, hint="", run_probe=False):
        super().__init__(name, hint)
        self.argv = list(argv)
        self.run_probe = run_probe

    def probe(self):
        resolved = shutil.which(self.argv[0])
        if resolved is None:
            return False, "not on PATH: %s" % self.argv[0]
        if not self.run_probe:
            return True, resolved
        try:
            p = subprocess.run(self.argv, capture_output=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, "would not start: %s" % exc
        if p.returncode != 0:
            return False, "exited with code %d" % p.returncode
        return True, resolved


class RegistryCheck(Check):
    """Required Windows registry value must exist (Windows only)."""

    def __init__(self, name, hive, subkey, value_name="", hint=""):
        super().__init__(name, hint)
        self.hive = hive
        self.subkey = subkey
        self.value_name = value_name

    def probe(self):
        try:
            import winreg
        except ImportError:
            return False, "winreg unavailable (not Windows?)"
        hive = getattr(winreg, self.hive, None)
        if hive is None:
            return False, "unknown hive: %s" % self.hive
        try:
            with winreg.OpenKey(hive, self.subkey) as key:
                if self.value_name:
                    val, _ = winreg.QueryValueEx(key, self.value_name)
                    return True, "%s=%r" % (self.value_name, val)
                return True, "key present"
        except OSError:
            return False, "absent: %s\\%s" % (self.hive, self.subkey)


class HealthReport:
    """Ordered check collection with structured rendering."""

    def __init__(self, title):
        self.title = title
        self.results = []

    def add(self, check):
        result = check.run()
        self.results.append(result)
        return result.ok

    def ok(self):
        return all(r.ok for r in self.results)

    @property
    def exit_code(self):
        return EXIT_OK if self.ok() else EXIT_BLOCKED

    def render(self, stream=None):
        out = stream or sys.stdout
        total = len(self.results)
        bad = [r for r in self.results if not r.ok]
        out.write("=" * 68 + "\n")
        out.write("  %s: %s (%d/%d checks passed)\n"
                  % (self.title, "HEALTHY" if not bad else "BLOCKED",
                     total - len(bad), total))
        out.write("=" * 68 + "\n")
        for r in self.results:
            out.write("[%s] %s\n" % ("+" if r.ok else "-", r.name))
            if r.detail:
                out.write("      detail: %s\n" % r.detail)
            if not r.ok and r.hint:
                out.write("      fix:    %s\n" % r.hint)
        if bad:
            out.write("Next single step is printed by the fallback router "
                      "below.\n")
        out.flush()


class Router:
    """Try named fallback steps in order; first success wins.

    Each step is (name, callable) where the callable returns True on success
    or a string describing what the user must do (guidance mode). Any
    exception inside a step is captured and reported as a failed attempt -
    never propagated.
    """

    def __init__(self):
        self.attempts = []  # (name, status, note)

    def add(self, name, func):
        self.attempts.append([name, func, None])
        return self

    def run(self, stream=None):
        out = stream or sys.stdout
        for entry in self.attempts:
            name, func = entry[0], entry[1]
            try:
                outcome = func()
            except Exception as exc:  # noqa: BLE001 - captured per contract
                entry[2] = "FAILED (%s: %s)" % (type(exc).__name__, exc)
                out.write("[-] fallback '%s': %s\n" % (name, entry[2]))
                continue
            if outcome is True:
                entry[2] = "OK"
                out.write("[+] fallback '%s': executed\n" % name)
                out.flush()
                return True
            entry[2] = "GUIDANCE"
            out.write("[*] fallback '%s': needs you -\n%s\n" % (name, outcome))
        out.flush()
        return False
