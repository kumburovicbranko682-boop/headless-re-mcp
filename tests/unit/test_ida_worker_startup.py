"""How a refused idalib open is described to the caller.

idalib opens a binary in place, so one sample has one database and a second
process asking for it is refused. That is a lock clearing on its own, and
telling an unattended caller it is permanent costs it the sample.
"""

from __future__ import annotations

from pathlib import Path

from headless_re_mcp.backends.ida.client import IdaWorkerError
from headless_re_mcp.backends.ida.worker import (
    _DATABASE_IN_USE,
    _MAX_INSN_TEXT,
    _bound_insn_text,
    _open_database_error,
    _page_envelope,
    _page_items,
)


def test_a_database_held_elsewhere_is_named_and_marked_retryable() -> None:
    """Code 4 was reported as a bare number and as permanent.

    Measured with two processes cycling one fixture, 40 of 50 opens failed this
    way, and none did when the same cycles ran one after another. batch.analyze
    opens up to eight static sessions at once, so the collision is something the
    surface invites rather than an accident.
    """
    error = _open_database_error(_DATABASE_IN_USE, Path(r"C:\samples\packed.exe"))

    assert "packed.exe" in str(error), "the caller has to know which sample"
    assert "already open in another process" in str(error)
    assert getattr(error, "retryable", False) is True


def test_any_other_open_failure_keeps_its_code_and_stays_permanent() -> None:
    """Only the one condition proven transient is described as transient."""
    error = _open_database_error(1, Path("sample.exe"))

    assert "code 1" in str(error), "an unclassified failure must still name its code"
    assert getattr(error, "retryable", False) is False


def test_the_worker_envelope_carries_retryable_through_to_the_client() -> None:
    """The flag is only useful if it survives the hop out of the worker."""
    payload = {
        "code": "worker_start_failed",
        "message": "RuntimeError: the IDA database for packed.exe is already open",
        "details": {},
        "retryable": True,
    }

    parsed = IdaWorkerError.from_payload(payload)

    assert parsed.code == "worker_start_failed"
    assert parsed.retryable is True


def test_a_static_page_at_the_cap_is_not_the_whole_list() -> None:
    """150 items with limit=100 used to come back as returned=100, no has_more.

    Every static.* list goes through this pager. A page sitting at the cap
    looked like the whole database, so the rest of the functions, strings or
    xrefs disappeared from whoever was supposed to walk them overnight.
    """
    items = [{"n": index} for index in range(150)]
    page = _page_items(items, 0, 100)
    assert page["returned"] == 100
    assert page["total"] == 150
    assert page["has_more"] is True
    tail = _page_items(items, 100, 100)
    assert tail["returned"] == 50
    assert tail["has_more"] is False


def test_a_hand_rolled_function_page_is_not_the_whole_list() -> None:
    """static.functions built the page itself and omitted has_more.

    The shared pager already carried the flag. functions and strings still
    assembled the envelope by hand, so a page of 100 of 150 looked complete.
    """
    window = [{"n": index} for index in range(100)]
    page = _page_envelope(window, 0, 100, 150)
    assert page["returned"] == 100
    assert page["total"] == 150
    assert page["has_more"] is True
    tail = _page_envelope([{"n": index} for index in range(100, 150)], 100, 100, 150)
    assert tail["returned"] == 50
    assert tail["has_more"] is False


def test_a_static_page_that_exactly_fills_is_complete() -> None:
    items = [{"n": index} for index in range(100)]
    page = _page_items(items, 0, 100)
    assert page["returned"] == 100
    assert page["total"] == 100
    assert page["has_more"] is False


def test_a_long_disassembly_line_says_it_was_cut() -> None:
    """600 characters used to come back as 512 with no truncated flag."""
    rendered, cut = _bound_insn_text("X" * (_MAX_INSN_TEXT + 88))
    assert cut is True
    assert len(rendered) == _MAX_INSN_TEXT


def test_a_short_disassembly_line_is_complete() -> None:
    rendered, cut = _bound_insn_text("mov rax, rbx")
    assert cut is False
    assert rendered == "mov rax, rbx"


def test_a_short_bytes_read_is_not_labelled_complete() -> None:
    """get_bytes returning 4 of 16 used to come back truncated=False."""
    import sys
    import types

    from headless_re_mcp.backends.ida.worker import _bytes_read

    ida = types.ModuleType("ida_bytes")
    ida.is_loaded = lambda address: True  # type: ignore[attr-defined]
    ida.get_bytes = lambda address, size: b"ABCD"  # type: ignore[attr-defined]
    sys.modules["ida_bytes"] = ida
    result = _bytes_read({"address": 0x1000, "size": 16})
    assert result["size"] == 4
    assert result["requested"] == 16
    assert result["hex"] == "41424344"
    assert result["truncated"] is True
    assert "fewer bytes" in str(result["note"])


def test_a_full_bytes_read_is_not_labelled_truncated() -> None:
    import sys
    import types

    from headless_re_mcp.backends.ida.worker import _bytes_read

    ida = types.ModuleType("ida_bytes")
    ida.is_loaded = lambda address: True  # type: ignore[attr-defined]
    ida.get_bytes = lambda address, size: b"ABCD"  # type: ignore[attr-defined]
    sys.modules["ida_bytes"] = ida
    result = _bytes_read({"address": 0x1000, "size": 4})
    assert result["size"] == 4
    assert result["requested"] == 4
    assert result["truncated"] is False
    assert "note" not in result


def _install_fake_bin_search(hits: list[int]) -> None:
    import sys
    import types

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x10000  # type: ignore[attr-defined]
    sys.modules["ida_ida"] = ida_ida

    ida_idaapi = types.ModuleType("ida_idaapi")
    ida_idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF  # type: ignore[attr-defined]
    sys.modules["ida_idaapi"] = ida_idaapi

    ida_bytes = types.ModuleType("ida_bytes")

    class compiled_binpat_vec_t:
        pass

    def bin_search(ea: int, end_ea: int, patterns: object, flags: int) -> int:
        for hit in hits:
            if hit >= ea:
                return hit
        return int(ida_idaapi.BADADDR)

    ida_bytes.compiled_binpat_vec_t = compiled_binpat_vec_t  # type: ignore[attr-defined]
    ida_bytes.parse_binpat_str = lambda patterns, ea, normalized, radix: True  # type: ignore[attr-defined]
    ida_bytes.bin_search = bin_search  # type: ignore[attr-defined]
    ida_bytes.BIN_SEARCH_FORWARD = 1  # type: ignore[attr-defined]
    ida_bytes.BIN_SEARCH_NOSHOW = 2  # type: ignore[attr-defined]
    sys.modules["ida_bytes"] = ida_bytes


def test_a_full_byte_search_page_is_not_every_hit() -> None:
    """150 hits with limit=100 used to come back total=100 has_more=False."""
    from headless_re_mcp.backends.ida.worker import _search_bytes

    _install_fake_bin_search(list(range(0x1000, 0x1000 + 150)))
    result = _search_bytes({"pattern": "C3", "offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["has_more"] is True
    assert result["total"] > 100


def test_an_exact_byte_search_page_is_complete() -> None:
    from headless_re_mcp.backends.ida.worker import _search_bytes

    _install_fake_bin_search(list(range(0x1000, 0x1000 + 100)))
    result = _search_bytes({"pattern": "C3", "offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["total"] == 100
    assert result["has_more"] is False


def _install_fake_text_search(hits: list[int]) -> None:
    import sys
    import types

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x10000  # type: ignore[attr-defined]
    sys.modules["ida_ida"] = ida_ida

    ida_idaapi = types.ModuleType("ida_idaapi")
    ida_idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF  # type: ignore[attr-defined]
    sys.modules["ida_idaapi"] = ida_idaapi

    idc = types.ModuleType("idc")
    idc.BADADDR = 0xFFFFFFFFFFFFFFFF  # type: ignore[attr-defined]
    sys.modules["idc"] = idc

    ida_search = types.ModuleType("ida_search")
    ida_search.SEARCH_DOWN = 1  # type: ignore[attr-defined]

    def find_text(ea: int, y: int, x: int, text: str, flags: int) -> int:
        for hit in hits:
            if hit >= ea:
                return hit
        return int(idc.BADADDR)

    ida_search.find_text = find_text  # type: ignore[attr-defined]
    sys.modules["ida_search"] = ida_search


def test_a_full_text_search_page_is_not_every_hit() -> None:
    """150 hits with limit=100 used to come back total=100 has_more=False."""
    from headless_re_mcp.backends.ida.worker import _search_text

    _install_fake_text_search(list(range(0x1000, 0x1000 + 150)))
    result = _search_text({"text": "hello", "offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["has_more"] is True
    assert result["total"] > 100


def test_an_exact_text_search_page_is_complete() -> None:
    from headless_re_mcp.backends.ida.worker import _search_text

    _install_fake_text_search(list(range(0x1000, 0x1000 + 100)))
    result = _search_text({"text": "hello", "offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["total"] == 100
    assert result["has_more"] is False


def _install_fake_imm_search(hits: list[int]) -> None:
    import sys
    import types

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x10000  # type: ignore[attr-defined]
    sys.modules["ida_ida"] = ida_ida

    ida_idaapi = types.ModuleType("ida_idaapi")
    ida_idaapi.BADADDR = 0xFFFFFFFFFFFFFFFF  # type: ignore[attr-defined]
    sys.modules["ida_idaapi"] = ida_idaapi

    idc = types.ModuleType("idc")
    idc.BADADDR = 0xFFFFFFFFFFFFFFFF  # type: ignore[attr-defined]
    sys.modules["idc"] = idc

    ida_search = types.ModuleType("ida_search")
    ida_search.SEARCH_DOWN = 1  # type: ignore[attr-defined]

    def find_imm(ea: int, flags: int, value: int) -> tuple[int, int] | int:
        for hit in hits:
            if hit >= ea:
                return (hit, 0)
        return int(idc.BADADDR)

    ida_search.find_imm = find_imm  # type: ignore[attr-defined]
    sys.modules["ida_search"] = ida_search


def test_a_full_immediate_search_page_is_not_every_hit() -> None:
    """150 hits with limit=100 used to come back total=100 has_more=False."""
    from headless_re_mcp.backends.ida.worker import _search_immediate

    _install_fake_imm_search(list(range(0x1000, 0x1000 + 150)))
    result = _search_immediate({"value": 1, "offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["has_more"] is True
    assert result["total"] > 100


def test_an_exact_immediate_search_page_is_complete() -> None:
    from headless_re_mcp.backends.ida.worker import _search_immediate

    _install_fake_imm_search(list(range(0x1000, 0x1000 + 100)))
    result = _search_immediate({"value": 1, "offset": 0, "limit": 100})
    assert result["returned"] == 100
    assert result["total"] == 100
    assert result["has_more"] is False


class _FakeFunc:
    def __init__(self, start: int, end: int) -> None:
        self.start_ea = start
        self.end_ea = end


def _install_fake_funcs(holder: dict[str, _FakeFunc | None]) -> None:
    import sys
    import types

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]
    sys.modules["ida_ida"] = ida_ida

    ida_funcs = types.ModuleType("ida_funcs")
    ida_funcs.get_func = lambda ea: holder["func"]  # type: ignore[attr-defined]
    ida_funcs.del_func = lambda start: True  # type: ignore[attr-defined]
    sys.modules["ida_funcs"] = ida_funcs


def test_a_function_that_is_still_there_is_not_deleted() -> None:
    """del_func True with the same function still present used to say deleted."""
    from headless_re_mcp.backends.ida.worker import WorkerRequestError, _function_delete

    _install_fake_funcs({"func": _FakeFunc(0x1000, 0x1100)})
    try:
        _function_delete({"address": 0x1000})
    except WorkerRequestError as exc:
        assert "still found" in str(exc)
        return
    raise AssertionError("a live function was reported deleted")


def test_a_removed_function_is_deleted() -> None:
    from headless_re_mcp.backends.ida.worker import _function_delete

    holder: dict[str, _FakeFunc | None] = {"func": _FakeFunc(0x1000, 0x1100)}

    import sys
    import types

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]
    sys.modules["ida_ida"] = ida_ida

    ida_funcs = types.ModuleType("ida_funcs")
    ida_funcs.get_func = lambda ea: holder["func"]  # type: ignore[attr-defined]

    def del_func(start: int) -> bool:
        holder["func"] = None
        return True

    ida_funcs.del_func = del_func  # type: ignore[attr-defined]
    sys.modules["ida_funcs"] = ida_funcs

    result = _function_delete({"address": 0x1000})
    assert result["deleted"] is True
    assert result["ok"] is True
    assert result["address"] == 0x1000


def _install_fake_names(holder: dict[str, str]) -> None:
    import sys
    import types

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]
    sys.modules["ida_ida"] = ida_ida

    ida_name = types.ModuleType("ida_name")
    ida_name.SN_FORCE = 1  # type: ignore[attr-defined]
    ida_name.set_name = lambda ea, name, flags: True  # type: ignore[attr-defined]
    sys.modules["ida_name"] = ida_name

    idc = types.ModuleType("idc")
    idc.get_name = lambda ea: holder["name"]  # type: ignore[attr-defined]
    sys.modules["idc"] = idc


def test_an_unchanged_name_is_not_set() -> None:
    """set_name True with the old name still present used to say ok=True."""
    from headless_re_mcp.backends.ida.worker import WorkerRequestError, _name_set

    _install_fake_names({"name": "old_name"})
    try:
        _name_set({"address": 0x1000, "name": "new_name"})
    except WorkerRequestError as exc:
        assert "still found" in str(exc)
        return
    raise AssertionError("an unchanged name was reported set")


def test_a_written_name_is_set() -> None:
    from headless_re_mcp.backends.ida.worker import _name_set

    holder = {"name": "old_name"}

    import sys
    import types

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]
    sys.modules["ida_ida"] = ida_ida

    ida_name = types.ModuleType("ida_name")
    ida_name.SN_FORCE = 1  # type: ignore[attr-defined]

    def set_name(ea: int, name: str, flags: int) -> bool:
        holder["name"] = name
        return True

    ida_name.set_name = set_name  # type: ignore[attr-defined]
    sys.modules["ida_name"] = ida_name

    idc = types.ModuleType("idc")
    idc.get_name = lambda ea: holder["name"]  # type: ignore[attr-defined]
    sys.modules["idc"] = idc

    result = _name_set({"address": 0x1000, "name": "new_name"})
    assert result["ok"] is True
    assert result["name"] == "new_name"
    assert result["previous_name"] == "old_name"


def test_setting_the_same_name_again_is_still_ok() -> None:
    from headless_re_mcp.backends.ida.worker import _name_set

    _install_fake_names({"name": "same_name"})
    result = _name_set({"address": 0x1000, "name": "same_name"})
    assert result["ok"] is True
    assert result["name"] == "same_name"


def _install_fake_comments(holder: dict[str, str]) -> None:
    import sys
    import types

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]
    sys.modules["ida_ida"] = ida_ida

    ida_bytes = types.ModuleType("ida_bytes")
    ida_bytes.get_cmt = lambda ea, repeatable: holder["comment"]  # type: ignore[attr-defined]
    ida_bytes.set_cmt = lambda ea, comment, repeatable: True  # type: ignore[attr-defined]
    sys.modules["ida_bytes"] = ida_bytes


def test_an_unchanged_comment_is_not_set() -> None:
    """set_cmt True with the old comment still present used to say ok=True."""
    from headless_re_mcp.backends.ida.worker import WorkerRequestError, _comment_set

    _install_fake_comments({"comment": "old comment"})
    try:
        _comment_set({"address": 0x1000, "comment": "new comment"})
    except WorkerRequestError as exc:
        assert "still found" in str(exc)
        return
    raise AssertionError("an unchanged comment was reported set")


def test_a_written_comment_is_set() -> None:
    from headless_re_mcp.backends.ida.worker import _comment_set

    holder = {"comment": "old comment"}

    import sys
    import types

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]
    sys.modules["ida_ida"] = ida_ida

    ida_bytes = types.ModuleType("ida_bytes")
    ida_bytes.get_cmt = lambda ea, repeatable: holder["comment"]  # type: ignore[attr-defined]

    def set_cmt(ea: int, comment: str, repeatable: bool) -> bool:
        holder["comment"] = comment
        return True

    ida_bytes.set_cmt = set_cmt  # type: ignore[attr-defined]
    sys.modules["ida_bytes"] = ida_bytes

    result = _comment_set({"address": 0x1000, "comment": "new comment"})
    assert result["ok"] is True
    assert result["comment"] == "new comment"
    assert result["previous_comment"] == "old comment"


def _install_fake_types(holder: dict[str, str]) -> None:
    import sys
    import types

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]
    sys.modules["ida_ida"] = ida_ida

    idc = types.ModuleType("idc")
    idc.get_type = lambda ea: holder["type"]  # type: ignore[attr-defined]
    idc.SetType = lambda ea, type_str: True  # type: ignore[attr-defined]
    sys.modules["idc"] = idc


def test_an_unchanged_type_is_not_applied() -> None:
    """SetType True with the old type still present used to say ok=True."""
    from headless_re_mcp.backends.ida.worker import WorkerRequestError, _type_apply

    _install_fake_types({"type": "int"})
    try:
        _type_apply({"address": 0x1000, "type": "char *"})
    except WorkerRequestError as exc:
        assert "still found" in str(exc)
        return
    raise AssertionError("an unchanged type was reported applied")


def test_a_written_type_is_applied() -> None:
    from headless_re_mcp.backends.ida.worker import _type_apply

    holder = {"type": "int"}

    import sys
    import types

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]
    sys.modules["ida_ida"] = ida_ida

    idc = types.ModuleType("idc")
    idc.get_type = lambda ea: holder["type"]  # type: ignore[attr-defined]

    def set_type(ea: int, type_str: str) -> bool:
        holder["type"] = type_str
        return True

    idc.SetType = set_type  # type: ignore[attr-defined]
    sys.modules["idc"] = idc

    result = _type_apply({"address": 0x1000, "type": "char *"})
    assert result["ok"] is True
    assert result["type"] == "char *"
    assert result["previous_type"] == "int"


def test_a_different_function_is_not_created() -> None:
    """add_func True with get_func pointing at another range used to say created."""
    import sys
    import types

    from headless_re_mcp.backends.ida.worker import WorkerRequestError, _function_create

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]
    sys.modules["ida_ida"] = ida_ida

    ida_funcs = types.ModuleType("ida_funcs")
    ida_funcs.get_func = lambda ea: _FakeFunc(0x0F00, 0x1100)  # type: ignore[attr-defined]
    ida_funcs.add_func = lambda ea: True  # type: ignore[attr-defined]
    sys.modules["ida_funcs"] = ida_funcs

    try:
        _function_create({"address": 0x1000})
    except WorkerRequestError as exc:
        assert "did not find a function starting" in str(exc)
        return
    raise AssertionError("another function's range was reported created")


def test_a_function_at_the_address_is_created() -> None:
    import sys
    import types

    from headless_re_mcp.backends.ida.worker import _function_create

    holder: dict[str, _FakeFunc | None] = {"func": None}

    ida_ida = types.ModuleType("ida_ida")
    ida_ida.inf_get_min_ea = lambda: 0x1000  # type: ignore[attr-defined]
    ida_ida.inf_get_max_ea = lambda: 0x2000  # type: ignore[attr-defined]
    sys.modules["ida_ida"] = ida_ida

    ida_funcs = types.ModuleType("ida_funcs")
    ida_funcs.get_func = lambda ea: holder["func"]  # type: ignore[attr-defined]

    def add_func(ea: int) -> bool:
        holder["func"] = _FakeFunc(ea, ea + 0x100)
        return True

    ida_funcs.add_func = add_func  # type: ignore[attr-defined]
    sys.modules["ida_funcs"] = ida_funcs

    result = _function_create({"address": 0x1000})
    assert result["created"] is True
    assert result["ok"] is True
    assert result["start"] == 0x1000
    assert result["end"] == 0x1100
