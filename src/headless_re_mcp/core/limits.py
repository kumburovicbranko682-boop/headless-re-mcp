"""Service-level bounds shared by the facade and the surfaces split out of it.

These were duplicated once AnalysisService started shedding mixins: the same
ceiling was declared in service.py and again in the module that moved out, which
is a limit that silently disagrees with itself the first time one side is tuned.
One definition, imported by everyone who enforces it.
"""

from __future__ import annotations

# Longest any single bounded debugger wait may be asked to run.
MAX_WORKFLOW_TIMEOUT = 300.0

# Refuse to dump more than this from one module in a single call.
MAX_MODULE_DUMP_BYTES = 64 * 1024 * 1024

# Static results larger than this are written to an artifact instead of inlined.
MAX_STATIC_INLINE_TEXT = 64 * 1024

# Commands accepted by one static.batch call.
MAX_STATIC_BATCH_COMMANDS = 32