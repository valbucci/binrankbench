"""
Regression tests for CCBHash implementation.

These tests ensure that the optimized implementation produces identical output
to the original implementation in dist/ccbhash.py. The original implementation
is the authoritative source of truth for hash consistency.
"""

import sys
from pathlib import Path
from typing import Any

import pytest

# Add dist to path to import original implementation
dist_path = Path(__file__).parent.parent / "dist"
if str(dist_path) not in sys.path:
    sys.path.insert(0, str(dist_path))

try:
    from ccbhash import _get_callgraph as original_get_callgraph # type: ignore
except ImportError:
    pytest.skip("Original ccbhash implementation not found in dist/", allow_module_level=True)

from binrankbench.modules.ccbhash import extract_call_graph, encode_graph
from binrankbench.common.types import R2CallGraph


# Test fixtures with known call graphs
@pytest.fixture
def simple_call_graph() -> R2CallGraph:
    """Simple call graph for testing."""
    return [
        {"name": "func_a", "size": 100, "imports": ["func_b", "func_c"]},
        {"name": "func_b", "size": 50, "imports": ["func_d"]},
        {"name": "func_c", "size": 75, "imports": []},
        {"name": "func_d", "size": 25, "imports": []},
    ]


@pytest.fixture
def complex_call_graph() -> R2CallGraph:
    """Complex call graph with cycles and multiple paths."""
    return [
        {"name": "main", "size": 200, "imports": ["init", "process", "cleanup"]},
        {"name": "init", "size": 100, "imports": ["setup"]},
        {"name": "process", "size": 150, "imports": ["validate", "execute"]},
        {"name": "cleanup", "size": 50, "imports": ["teardown"]},
        {"name": "setup", "size": 30, "imports": []},
        {"name": "validate", "size": 40, "imports": []},
        {"name": "execute", "size": 60, "imports": ["validate"]},  # Cycle
        {"name": "teardown", "size": 20, "imports": []},
    ]


@pytest.fixture
def single_function_call_graph() -> R2CallGraph:
    """Call graph with single function."""
    return [
        {"name": "isolated_func", "size": 50, "imports": []},
    ]


@pytest.fixture
def empty_imports_call_graph() -> R2CallGraph:
    """Call graph where function has no imports."""
    return [
        {"name": "func_no_imports", "size": 100, "imports": []},
        {"name": "func_with_imports", "size": 100, "imports": ["func_no_imports"]},
    ]


def test_extract_call_graph_matches_original_simple(simple_call_graph: R2CallGraph):
    """Test that extract_call_graph produces same output as original for simple graph."""
    func_name = "func_a"
    
    # Get original output (returns string directly)
    original_output = original_get_callgraph(func_name, simple_call_graph)
    
    # Get current output (returns tuple, needs encoding)
    func_call_graph, func_indexes = extract_call_graph(func_name, simple_call_graph)
    current_output = encode_graph(func_call_graph, func_indexes, is_cfg=False)
    
    assert original_output == current_output, (
        f"Call graph encoding mismatch for {func_name}\n"
        f"Original: {original_output!r}\n"
        f"Current:  {current_output!r}"
    )


def test_extract_call_graph_matches_original_complex(complex_call_graph: R2CallGraph):
    """Test that extract_call_graph produces same output as original for complex graph."""
    func_name = "main"
    
    # Get original output
    original_output = original_get_callgraph(func_name, complex_call_graph)
    
    # Get current output
    func_call_graph, func_indexes = extract_call_graph(func_name, complex_call_graph)
    current_output = encode_graph(func_call_graph, func_indexes, is_cfg=False)
    
    assert original_output == current_output, (
        f"Call graph encoding mismatch for {func_name}\n"
        f"Original: {original_output!r}\n"
        f"Current:  {current_output!r}"
    )


def test_extract_call_graph_matches_original_single_function(
    single_function_call_graph: R2CallGraph
):
    """Test that extract_call_graph handles single function correctly."""
    func_name = "isolated_func"
    
    # Get original output
    original_output = original_get_callgraph(func_name, single_function_call_graph)
    
    # Get current output
    func_call_graph, func_indexes = extract_call_graph(func_name, single_function_call_graph)
    current_output = encode_graph(func_call_graph, func_indexes, is_cfg=False)
    
    assert original_output == current_output, (
        f"Call graph encoding mismatch for {func_name}\n"
        f"Original: {original_output!r}\n"
        f"Current:  {current_output!r}"
    )


def test_extract_call_graph_matches_original_empty_imports(
    empty_imports_call_graph: R2CallGraph
):
    """Test that extract_call_graph handles functions with no imports correctly."""
    func_name = "func_no_imports"
    
    # Get original output
    original_output = original_get_callgraph(func_name, empty_imports_call_graph)
    
    # Get current output
    func_call_graph, func_indexes = extract_call_graph(func_name, empty_imports_call_graph)
    current_output = encode_graph(func_call_graph, func_indexes, is_cfg=False)
    
    assert original_output == current_output, (
        f"Call graph encoding mismatch for {func_name}\n"
        f"Original: {original_output!r}\n"
        f"Current:  {current_output!r}"
    )


def test_extract_call_graph_preserves_import_order(simple_call_graph: R2CallGraph):
    """Test that import order is preserved (not sorted)."""
    func_name = "func_a"
    
    # Extract call graph
    func_call_graph, func_indexes = extract_call_graph(func_name, simple_call_graph)
    
    # Check that imports are in original order (func_b, func_c), not sorted
    imports = func_call_graph[func_name]
    assert imports == ["func_b", "func_c"], (
        f"Import order not preserved. Expected ['func_b', 'func_c'], got {imports}"
    )


def test_extract_call_graph_bfs_order(simple_call_graph: R2CallGraph):
    """Test that functions are processed in BFS discovery order, not alphabetical."""
    func_name = "func_a"
    
    # Extract call graph
    func_call_graph, func_indexes = extract_call_graph(func_name, simple_call_graph)
    
    # In BFS order: func_a (0), func_b (1), func_c (2), func_d (3)
    # NOT alphabetical: func_a, func_b, func_c, func_d (would be same in this case)
    # But if we had func_z, func_a, func_b, BFS would give: func_a, func_b, func_z
    # while alphabetical would give: func_a, func_b, func_z (different order)
    
    # Check that func_a is index 0 (root)
    assert func_indexes[func_name] == "0"
    
    # Check that func_b and func_c are next (discovered from func_a)
    assert func_indexes["func_b"] == "1" or func_indexes["func_b"] == "2"
    assert func_indexes["func_c"] == "1" or func_indexes["func_c"] == "2"
    
    # Check that func_d is last (discovered from func_b)
    assert func_indexes["func_d"] == "3"


def test_encode_graph_matches_original_format(simple_call_graph: R2CallGraph):
    """Test that encode_graph produces same format as original."""
    func_name = "func_a"
    
    # Get original output
    original_output = original_get_callgraph(func_name, simple_call_graph)
    
    # Get current output
    func_call_graph, func_indexes = extract_call_graph(func_name, simple_call_graph)
    current_output = encode_graph(func_call_graph, func_indexes, is_cfg=False)
    
    # Verify format matches: "index:output1,output2,...;"
    assert original_output == current_output
    
    # Verify format structure
    parts = current_output.split(";")
    for part in parts:
        if part:  # Skip empty parts
            assert ":" in part, f"Invalid format: {part}"
            index, outputs = part.split(":", 1)
            assert index.isdigit(), f"Index should be digit: {index}"


@pytest.mark.parametrize("func_name", ["func_a", "func_b", "func_c", "func_d"])
def test_all_functions_match_original(simple_call_graph: R2CallGraph, func_name: str):
    """Test that all functions in simple graph match original."""
    # Get original output
    original_output = original_get_callgraph(func_name, simple_call_graph)
    
    # Get current output
    func_call_graph, func_indexes = extract_call_graph(func_name, simple_call_graph)
    current_output = encode_graph(func_call_graph, func_indexes, is_cfg=False)
    
    assert original_output == current_output, (
        f"Call graph encoding mismatch for {func_name}\n"
        f"Original: {original_output!r}\n"
        f"Current:  {current_output!r}"
    )

