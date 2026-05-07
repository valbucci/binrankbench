"""
CFG (Control Flow Graph) extraction utilities.

This module provides common utilities for extracting control flow graphs
from radare2 function data.
"""

from typing import Optional

from binrankbench.common.types import (
    R2CodeInfoIn, R2BlockInfoIn, BlockEdges, BlockOffset
)
from binrankbench.common.utils import get_address, is_address_placeholder
from binrankbench.common.hex import HexOffset


def extract_cfg_edges(func_code: R2CodeInfoIn
                      ) -> tuple[dict[int, R2BlockInfoIn], BlockEdges]:
    """
    Extract CFG edges and block data from function code.
    
    Args:
        func_code: Function code from r2 agfj command.
        
    Returns:
        A tuple of (blocks, edges) where:
        - blocks: Maps block offsets (int) to block data
        - edges: Maps source block offsets to lists of destination offsets
    
    Example:
        >>> blocks, edges = extract_cfg_edges(func_code)
        >>> for src, dests in edges.items():
        ...     print(f"Block {src:x} -> {[f'{d:x}' for d in dests]}")
    """
    blocks: dict[int, R2BlockInfoIn] = {}
    edges: BlockEdges = {}
    
    for block in func_code.get("blocks", []):
        offset = get_address(block)
        blocks[offset] = block
        
        # Extract edges (jump and fail targets)
        successors: list[BlockOffset] = []
        
        fail_val = block.get("fail")
        if fail_val is not None and not is_address_placeholder(fail_val):
            successors.append(HexOffset(fail_val))
        
        jump_val = block.get("jump")
        if jump_val is not None and not is_address_placeholder(jump_val):
            successors.append(HexOffset(jump_val))
        
        edges[HexOffset(offset)] = successors
    
    return blocks, edges


def count_edges(edges: BlockEdges) -> int:
    """Count total number of edges in the CFG."""
    return sum(len(succs) for succs in edges.values())


def get_source_blocks(edges: BlockEdges) -> set[int]:
    """Get all blocks that have outgoing edges."""
    sources = set()
    for src, succs in edges.items():
        if succs:  # Has at least one outgoing edge
            sources.add(int(src))
    return sources


def get_destination_blocks(edges: BlockEdges) -> set[int]:
    """Get all blocks that receive incoming edges."""
    destinations = set()
    for succs in edges.values():
        for dst in succs:
            destinations.add(int(dst))
    return destinations




