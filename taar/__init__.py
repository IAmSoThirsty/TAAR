"""TAAR — Thirsty's Active Agent Runner.

A local-first governed automation taskforce for Project-AI.
Reader/writer separation, evidence bundles, classification, quarantine,
append-only audit, fail-closed admission. Nothing merges itself.
"""

__version__ = "0.1.0"

# Import-path bridge: in the repo layout, `checks/` and `writers/` are
# top-level; installed via pip they are packaged as `taar.checks` and
# `taar.writers`. Canonical import path is taar.checks / taar.writers.
import importlib as _importlib
import sys as _sys

for _name in ("checks", "writers"):
    _qualified = f"taar.{_name}"
    if _qualified not in _sys.modules:
        try:
            _importlib.import_module(_qualified)
        except ImportError:
            try:
                _sys.modules[_qualified] = _importlib.import_module(_name)
            except ImportError:
                pass
