from __future__ import annotations

from pathlib import Path

from headless_re_mcp.core.events import parse_debug_event_batch

ROOT = Path(__file__).resolve().parents[2]


def test_ida_worker_persists_the_database_on_close() -> None:
    worker = (ROOT / 'src/headless_re_mcp/backends/ida/worker.py').read_text(encoding='utf-8')
    assert 'close_database(True)' in worker
    assert 'close_database(False)' not in worker
    gate = (ROOT / 'src/headless_re_mcp/backends/ida/gate_worker.py').read_text(encoding='utf-8')
    assert 'close_database(True)' in gate
    assert 'close_database(False)' not in gate


def test_native_rpc_cancels_gui_work_after_dispatch_timeout() -> None:
    source = (ROOT / 'native/xdbg-headless-rpc/rpc_server.cpp').read_text(encoding='utf-8')
    assert 'cancelled.store(true)' in source
    assert 'job->cancelled.load()' in source


def test_native_event_callback_records_an_unrecovered_gap() -> None:
    source = (ROOT / 'native/xdbg-headless-rpc/rpc_events.cpp').read_text(encoding='utf-8')
    assert 'EventKind::UnrecoveredGap' in source
    assert 'debug.unrecovered_gap' in source


def test_unrecovered_gap_event_kind_is_accepted() -> None:
    payload = {
        'events': [{
            'sequence': 1,
            'timestamp_unix_ms': 1_700_000_000_001,
            'source': 'x64dbg.plugin_callback',
            'kind': 'debug.unrecovered_gap',
            'data': {},
        }],
        'count': 1,
        'cursor': 0,
        'next_cursor': 1,
        'oldest_sequence': 1,
        'latest_sequence': 1,
        'dropped': 0,
        'dropped_total': 0,
        'has_more': False,
        'capacity': 1024,
    }
    batch = parse_debug_event_batch(payload, requested_cursor=0, requested_limit=100)
    assert batch.events[0].kind == 'debug.unrecovered_gap'


def test_cli_children_are_assigned_to_the_process_job() -> None:
    die = (ROOT / 'src/headless_re_mcp/detection/die.py').read_text(encoding='utf-8')
    upx = (ROOT / 'src/headless_re_mcp/unpack/upx.py').read_text(encoding='utf-8')
    exe = (ROOT / 'src/headless_re_mcp/detection/exeinfope.py').read_text(encoding='utf-8')
    assert 'assign_to_process_group' in die
    assert 'assign_to_process_group' in upx
    assert 'assign_to_process_group' in exe


def test_rpc_pipe_acl_failure_retries_instead_of_exiting() -> None:
    source = (ROOT / 'native/xdbg-headless-rpc/rpc_server.cpp').read_text(encoding='utf-8')
    assert 'Sleep(1000)' in source
    assert source.count('return;') >= 1


def test_patch_restore_walks_consecutive_bytes() -> None:
    source = (ROOT / 'native/xdbg-headless-rpc/rpc_methods.cpp').read_text(encoding='utf-8')
    assert 'restored_bytes' in source
    assert 'PatchRestore(cursor)' in source


def test_native_module_and_thread_lists_are_paged() -> None:
    source = (ROOT / 'native/xdbg-headless-rpc/rpc_methods.cpp').read_text(encoding='utf-8')
    assert 'Outcome ListModules(const json_t* params)' in source
    assert 'Outcome ListThreads(const json_t* params)' in source
    assert 'has_more' in source


def test_unpack_cancel_signals_in_flight_dumpers() -> None:
    service = (ROOT / 'src/headless_re_mcp/core/service_unpack.py').read_text(encoding='utf-8')
    cli = (ROOT / 'src/headless_re_mcp/core/service_unpack_cli.py').read_text(encoding='utf-8')
    capture = (ROOT / 'src/headless_re_mcp/dotnet/de4dot.py').read_text(encoding='utf-8')
    assert '_signal_unpack_cancel' in service
    assert 'bound_cancel_scope' in cli
    assert 'BoundedCancelled' in capture
