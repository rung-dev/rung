"""Packaging conformance: the in-session-provable slice of the PyPI packaging
work. Wheel build/install criteria are environment-gated and NOT exercised
here; these prove the resolution logic and the console-script contract with
src/ on sys.path. Stdlib only.

Run:  python3 gate/test_packaging.py
This file inserts REPO/src on sys.path itself, so it also runs under a plain
`python3 -m unittest` from the repo root.
"""
import contextlib
import importlib.resources
import io
import os
import pathlib
import re
import sys
import unittest
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

FLAGSHIP = REPO / "cases" / "sync-connector-stdio-purity" / "bundle.json"
BUNDLED_POLICY = SRC / "rung" / "data" / "default_policy.json"
SOURCE_POLICY = REPO / "policy" / "default.json"
PYPROJECT = REPO / "pyproject.toml"


@contextlib.contextmanager
def _muffle():
    """Swallow a main()'s stdout/stderr so the test log stays clean."""
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        yield


class ResolverHappyPath(unittest.TestCase):
    """US2 AC5: with src/ on the path, the resolver yields the bundled default's
    real bytes and gating with no explicit policy succeeds."""

    def test_default_policy_path_yields_bundled_bytes(self):
        import rung.gate as gate
        with gate.default_policy_path() as p:
            got = pathlib.Path(p).read_bytes()
        self.assertEqual(got, BUNDLED_POLICY.read_bytes())

    def test_gate_default_policy_passes_flagship(self):
        import rung.gate as gate
        with _muffle():
            rc = gate.main([str(FLAGSHIP)])
        self.assertEqual(rc, gate.EXIT_PASS)


class ResolverFailClosed(unittest.TestCase):
    """US2 AC4 (NOT env-gated): a missing/unreadable bundled default policy fails
    closed to exit 2 with no traceback, in BOTH entrypoints. as_file() raises at
    context entry on the zipimport/missing-resource case; the resolver must
    translate that to gate.GateInputError so main()'s existing catch handles it."""

    def test_resolver_translates_missing_resource_to_gateinputerror(self):
        import rung.gate as gate
        with mock.patch("importlib.resources.files", side_effect=FileNotFoundError("boom")):
            with self.assertRaises(gate.GateInputError):
                with gate.default_policy_path():
                    pass

    def test_gate_missing_default_policy_exits_2(self):
        import rung.gate as gate
        with mock.patch("importlib.resources.files", side_effect=FileNotFoundError("boom")):
            with _muffle():
                rc = gate.main([str(FLAGSHIP)])
        self.assertEqual(rc, gate.EXIT_USAGE)

    def test_run_missing_default_policy_exits_2(self):
        import rung.run as run
        import rung.gate as gate
        with mock.patch("importlib.resources.files", side_effect=FileNotFoundError("boom")):
            with _muffle():
                rc = run.main(["--rung", "3", "--surface", "cli", "--tier", "medium",
                               "--", sys.executable, "-c", "print('hi')"])
        self.assertEqual(rc, gate.EXIT_USAGE)


class ConsoleScriptContract(unittest.TestCase):
    """US3 AC4: the console-script wrapper invokes main() with NO args, so main
    must read sys.argv[1:] itself and return an int, never raise TypeError. This
    is not covered by `python -m rung.cli` (that path passes sys.argv[1:]
    explicitly via the __main__ block)."""

    def _zero_arg_main(self, mod, argv):
        saved = sys.argv
        sys.argv = argv
        try:
            with _muffle():
                rc = mod.main()  # no args -> must read sys.argv[1:]
        finally:
            sys.argv = saved
        self.assertIsInstance(rc, int)
        return rc

    def test_cli_zero_arg_main(self):
        import rung.cli as cli
        self.assertEqual(self._zero_arg_main(cli, ["rung", "gate", str(FLAGSHIP)]), 0)

    def test_gate_zero_arg_main(self):
        import rung.gate as gate
        self.assertEqual(self._zero_arg_main(gate, ["gate", str(FLAGSHIP)]), 0)

    def test_run_zero_arg_main(self):
        import rung.run as run
        # Valid flags but no probe -> run's own no-probe usage error (int 2). This
        # exercises the zero-arg main path while getting past argparse's required
        # --rung/--surface (a bare ["run"] would SystemExit in _parse before the
        # int return, testing argparse rather than main's argv defaulting).
        self.assertEqual(
            self._zero_arg_main(run, ["run", "--rung", "1", "--surface", "cli"]), 2)


class PackagingArtifacts(unittest.TestCase):
    """Structural guards on the src/ layout that need no wheel build: the
    two-copy policy invariant, the removed parent.parent resolution, and the
    empty runtime-dependency contract. Text-level (not tomllib) so they run on
    the 3.9 floor, where no stdlib TOML parser exists."""

    def test_bundled_policy_byte_identical_to_source(self):
        # The repo keeps two copies of the default policy: policy/default.json
        # (what the in-process test suites read) and src/rung/data/default_policy.json
        # (what ships in the wheel and importlib.resources resolves). There is no
        # build-time copy step in-repo, so this byte-for-byte check is the SOLE
        # guard against the two drifting apart. Read as bytes so whitespace drift
        # is caught, not normalized away.
        self.assertEqual(BUNDLED_POLICY.read_bytes(), SOURCE_POLICY.read_bytes(),
                         "src/rung/data/default_policy.json must stay byte-identical to policy/default.json")

    def test_no_parent_parent_policy_resolution(self):
        # US1 AC3: default-policy resolution no longer walks parent.parent from
        # __file__ in either entrypoint (the bug that broke reads after install).
        for name in ("gate.py", "run.py"):
            src = (SRC / "rung" / name).read_text()
            self.assertNotIn(".parent.parent", src,
                             f"{name} must not resolve any path via .parent.parent")

    def test_pyproject_declares_empty_runtime_deps(self):
        # US5 AC2: the runtime is dependency-free forever. A build backend under
        # [build-system].requires is build-time only and does not count.
        text = PYPROJECT.read_text()
        self.assertIsNotNone(
            re.search(r"(?m)^dependencies\s*=\s*\[\s*\]\s*$", text),
            "pyproject.toml [project].dependencies must be an empty list")

    def test_pyproject_console_script_entry(self):
        # US3: the installed `rung` command dispatches to rung.cli:main.
        text = PYPROJECT.read_text()
        self.assertIsNotNone(
            re.search(r'(?m)^rung\s*=\s*"rung\.cli:main"\s*$', text),
            "pyproject.toml must declare [project.scripts] rung = \"rung.cli:main\"")


if __name__ == "__main__":
    unittest.main(verbosity=2)
