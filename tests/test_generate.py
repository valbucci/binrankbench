import pytest
from pathlib import Path

from binrankbench.modules.generate.tasks import TaskGroup, TaskWrapper
from binrankbench.modules.generate.result import (CCBHashResult, MachokeResult, Catalog1Result,
                                      BytesResult, FunctionDetailsResult,
                                      FunctionSimSearchResult, SkipInfo)


@pytest.fixture(scope="function")
def output_dir(tmp_path):
    """Create a temporary output directory for tests."""
    output = tmp_path / "output"
    output.mkdir()
    return output


# ===== Unit Tests for Result Serialization =====

def test_ccbhash_result_csv_serialization():
    """Test CCBHashResult CSV serialization."""
    result = CCBHashResult(
        func_addr=0x140001180,
        success=True,
        ccbhash_features=None  # Will be empty row
    )

    headers = result.csv_headers()
    row = result.to_csv_row()

    assert headers[0] == "func_addr"
    assert headers[1] == "name"
    assert headers[2] == "ccbhash"
    assert len(headers) == 15
    assert row[0] == "140001180"
    assert len(row) == 15


def test_machoke_result_csv_serialization():
    """Test MachokeResult CSV serialization."""
    result = MachokeResult(
        func_addr=0x140001180,
        success=True,
        machoke_line="test_line",
        machoke_digest="abcd1234"
    )

    headers = result.csv_headers()
    row = result.to_csv_row()

    assert headers == ["func_addr", "machoke_digest", "machoke_line"]
    assert row == ["140001180", "abcd1234", "test_line"]


def test_catalog1_result_csv_serialization():
    """Test Catalog1Result CSV serialization."""
    result = Catalog1Result(
        func_addr=0x140001180,
        success=True,
        catalog1="catalog1_hash",
    )

    headers = result.csv_headers()
    row = result.to_csv_row()

    assert "func_addr" in headers
    assert "catalog1" in headers
    assert row[0] == "140001180"
    assert row[1] == "catalog1_hash"


def test_bytes_result_csv_serialization():
    """Test BytesResult CSV serialization with encoded bytes."""
    result = BytesResult.from_raw_bytes(
        func_addr=0x140001180,
        success=True,
        raw_bytes=b"\x48\x89\x5c\x24\x08",
        nibble_sig_mask=b"\x48\x00\x5c\x00\x08",
        bit_sig_mask=b"\x48\x88\x5c\x24\x08"
    )

    headers = result.csv_headers()
    row = result.to_csv_row()

    assert headers == ["func_addr", "raw_bytes", "nibble_sig_mask",
                       "bit_sig_mask"]
    assert row[0] == "140001180"
    assert row[1] != ""  # Should have encoded bytes
    assert row[2] != ""
    assert row[3] != ""


def test_function_details_result_csv_serialization():
    """Test FunctionDetailsResult CSV serialization."""
    result = FunctionDetailsResult(
        func_addr=0x140001180,
        success=True,
        name="test_function",
        size=100,
        ninstructions=25
    )

    headers = result.csv_headers()
    row = result.to_csv_row()

    assert "func_addr" in headers
    assert "name" in headers
    assert "size" in headers
    assert row[0] == "140001180"
    assert row[2] == "test_function"


def test_fss_result_csv_serialization():
    """Test FunctionSimSearchResult CSV serialization."""
    result = FunctionSimSearchResult(
        func_addr=0x140001180,
        success=True,
        fss_plain="fss_hash",
        mss_plain="mss_hash"
    )

    headers = result.csv_headers()
    row = result.to_csv_row()

    assert "fss_plain" in headers
    assert "mss_plain" in headers
    assert row[0] == "140001180"


# ===== Unit Tests for TaskGroup =====

def test_task_group_prepare_tasks(output_dir, binary_name):
    """Test TaskGroup only creates tasks when required data is available."""
    # Test with minimal data (only bytes)
    task_group_minimal = TaskGroup(
        binary_name=binary_name,
        output_dir=output_dir,
        func_addr=0x140001180,
        func_name="test_func",
        func_info=None,
        func_zignature=None,
        func_code=None,
        func_callgraph=None,
        func_bytes=b"\x48\x89\x5c\x24\x08",
        bit_masked_func_bytes=None
    )

    minimal_wrappers, minimal_skips, minimal_checkpointed = task_group_minimal.prepare_tasks()

    # Should only create 2 tasks: catalog1, bytes (no CFG = no machoke/ccbhash/fss)
    assert len(minimal_wrappers) == 2
    minimal_types = {type(w.task).__name__ for w in minimal_wrappers}
    assert minimal_types == {"Catalog1Task", "BytesTask"}
    # Should record skipped tasks for unavailable data sources
    assert len(minimal_skips) > 0
    assert not minimal_checkpointed

    # Test with complete data (using type: ignore for test data)
    task_group_complete = TaskGroup(
        binary_name=binary_name,
        output_dir=output_dir,
        func_addr=0x140001180,
        func_name="test_func",
        func_info={"name": "test", "size": 100},  # type: ignore
        func_zignature={"bytes": "48895c2408", "mask": "ffffffffff"},  # type: ignore
        func_code={"blocks": []},  # type: ignore
        func_callgraph={"imports": [], "calls": []},  # type: ignore
        func_bytes=b"\x48\x89\x5c\x24\x08",
        bit_masked_func_bytes=b"\x48\x89\x5c\x24\x08"
    )

    complete_wrappers, complete_skips, complete_checkpointed = task_group_complete.prepare_tasks()

    # Should create base tasks plus variant tasks
    # Base tasks: MachokeTask, CCBHashTask, Catalog1Task,
    #             BytesTask, FunctionDetailsTask, FunctionSimSearchTask
    base_task_types = {"MachokeTask", "CCBHashTask",
                      "Catalog1Task", "BytesTask", "FunctionDetailsTask", "FunctionSimSearchTask"}

    task_types = {type(w.task).__name__ for w in complete_wrappers}

    # Check that all base tasks are present
    assert base_task_types.issubset(task_types), \
        f"Missing base tasks. Expected: {base_task_types}, Got: {task_types}"

    # Just verify we have at least the base tasks
    assert len(complete_wrappers) >= len(base_task_types), \
        f"Expected at least {len(base_task_types)} tasks, got {len(complete_wrappers)}"

    assert not complete_skips
    assert not complete_checkpointed

    # Check all have correct address and output paths
    for wrapper in complete_wrappers:
        assert isinstance(wrapper, TaskWrapper)
        assert wrapper.func_addr == 0x140001180
        assert wrapper.output_path.parent == output_dir
        assert wrapper.output_path.name.startswith(binary_name)
