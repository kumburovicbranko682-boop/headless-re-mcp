"""Shared x64dbg headless RPC size limits (keep in sync with native rpc_internal.h)."""

from __future__ import annotations

# Must match native/xdbg-headless-rpc/rpc_internal.h
MAX_FRAME_BYTES = 8 * 1024 * 1024
MAX_MEMORY_BYTES = 2 * 1024 * 1024
MAX_IMPORT_SCAN_BYTES = 16 * 1024 * 1024
MAX_DUMP_BYTES = 64 * 1024 * 1024