"""Tripwire: no test may fake ``os.name`` on the process-wide os module.

``pathlib.Path()`` dispatches on ``os.name`` at call time. While a global
fake is active, every ``Path(...)`` in the process mints the other platform's
flavour, which Python 3.11 refuses to instantiate (``NotImplementedError``).
Worse, when such a test *fails*, the fake is still active while pytest formats
the failure report -- its own ``Path(os.getcwd())`` then crashes too, and the
whole session aborts with INTERNALERROR, masking every result after it. This
took down linux-quality (3.11) on main once already.

The supported pattern is a module-scoped proxy pinning what the code under
test reads (see ``_OsProxy`` in ``test_config_discovery_paths.py``)::

    monkeypatch.setattr(module_under_test, "os", _OsProxy("nt"))

This test exists so a branch reintroducing the global fake fails fast, on
every platform, with this explanation -- instead of as a 3.11-only session
crash that names no culprit.
"""

from __future__ import annotations

import re
from pathlib import Path

_FORBIDDEN = re.compile(r'setattr\(\s*os\s*,\s*"name"|setattr\(\s*"os\.name"')


def test_no_test_fakes_os_name_on_the_shared_os_module() -> None:
    this_file = Path(__file__).resolve()
    offenders: list[str] = []
    for path in sorted(this_file.parent.rglob("*.py")):
        if path.resolve() == this_file:
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if _FORBIDDEN.search(line):
                offenders.append(f"{path.name}:{number}: {line.strip()}")
    assert not offenders, (
        "process-wide os.name fakes poison pathlib on Python 3.11 and crash "
        "pytest's own failure reporting; pin a module-scoped proxy instead "
        "(see this file's docstring):\n" + "\n".join(offenders)
    )
