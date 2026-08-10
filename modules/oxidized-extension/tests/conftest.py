"""Make oxidized_extension.__main__ importable without an ActiveGate.

__main__.py imports dynatrace_extension at module scope. The SDK is a genuine runtime
dependency (see setup.py — the EEC runtime does NOT provide it, proven on a real ActiveGate
2026-08-01), but these are pure-logic tests and coupling them to an SDK install would mean
the suite passes or fails depending on which venv a developer happens to be in.

The stub is installed UNCONDITIONALLY, not just when the import fails, for two reasons:
  1. Hermetic. The tests behave identically on a machine with the SDK and one without.
  2. The real Extension defines __del__, which calls self._callbacks_executor.shutdown().
     The extension-level tests build their instance with object.__new__ to avoid starting an
     SDK lifecycle, so that attribute never exists and every garbage-collected instance
     raised PytestUnraisableExceptionWarning — noise that would eventually hide a real one.

Nothing here fakes behaviour under test: __main__.py only ever uses the base class for
schedule/logger/get_activation_config/report_log_events, all of which the tests supply
themselves.
"""
import sys
import types

_stub = types.ModuleType("dynatrace_extension")
_stub.Extension = type("Extension", (), {})
sys.modules["dynatrace_extension"] = _stub
