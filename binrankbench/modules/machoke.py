"""Machoke: graph-feature function hash based on CFG structure and opcode statistics."""

from typing import Optional, TypedDict
from collections import OrderedDict

from binrankbench.common.types import R2CodeInfoIn, R2OpcodeInfoIn, R2BlockInfoIn
from binrankbench.common.hex import HexStr
from binrankbench.common.utils import get_address, is_address_placeholder
import mmh3


def is_call_instruction(instruction: R2OpcodeInfoIn) -> bool:
    """Returns True if the instruction is a call instruction."""
    if "call" in instruction["type"]:
        # Handle types call, ucall, icall, rcall, ircall, uccall
        return True
    # The instruction could be mov and still be a call reference
    # so we need to check the references
    refs = instruction.get("refs")
    if refs is None or len(refs) == 0:
        # No references, so it's not a call
        return False
    # Check if any of the references is a call
    return any(ref["type"] == "CALL" for ref in refs)

def is_block_call_terminated(block: R2BlockInfoIn) -> bool:
    """Returns True if the block is a call terminated block."""
    last_instruction = block["ops"][-1]
    return is_call_instruction(last_instruction)

def get_instruction_successors(instruction: R2OpcodeInfoIn) -> set[int]:
    """Returns the CFG successor addresses of an instruction."""
    successors = set()
    op_type = instruction["type"]
    op_addr = get_address(instruction)
    size = instruction.get("size", 0)
    
    # 1. Get references from jump/ptr/fail fields
    jump_addr = instruction.get("jump")
    fail_addr = instruction.get("fail")
    ptr_addr = instruction.get("ptr")
    
    if op_type == "cjmp":
        # Conditional jump: add the jump address if it is set
        if not is_address_placeholder(jump_addr):
            successors.add(jump_addr)
        # Fallthrough: check if there is a fail address, otherwise compute
        # instruction address + size
        if not is_address_placeholder(fail_addr):
            successors.add(fail_addr)
        elif isinstance(size, int) and size > 0:
            successors.add(op_addr + size)
            
    elif op_type == "jmp":
        # Unconditional jump: add the jump address if it is set (no fallthrough)
        if not is_address_placeholder(ptr_addr):
            successors.add(ptr_addr)
        elif not is_address_placeholder(jump_addr):
            successors.add(jump_addr)
            
    elif op_type.endswith("jmp"):
        # Capture other jump variants like ujmp, ijmp, mjmp, etc.
        # Same as above but keeping it separate for clarity
        if not is_address_placeholder(ptr_addr):
            successors.add(ptr_addr)
        elif not is_address_placeholder(jump_addr):
            successors.add(jump_addr)
            
    #2. Get references from refs
    refs = instruction.get("refs")
    if refs is not None:
        for ref in refs:
            ref_type = ref["type"]
            ref_addr = ref["addr"]
            if is_address_placeholder(ref_addr):
                continue
            
            if ref_type in ("CODE", "ICOD"):
                successors.add(ref_addr)
                
            # Ignoring DATA, STRN, CALL, etc.
            
    return successors


def get_block_successor_addresses(block: R2BlockInfoIn) -> set[int]:
    """Returns the CFG successor addresses of a basic block."""
    successors = set()
    # 1. Get block-level edges
    for key in ("jump", "fail"):
        addr = block.get(key)
        if not is_address_placeholder(addr):
            successors.add(addr)

    # 2. Get instruction-level edges
    for instruction in block["ops"]:
        instruction_successors = get_instruction_successors(instruction)
        successors.update(instruction_successors)

    return successors

def make_fallthrough_block(
    ops: list[R2OpcodeInfoIn],
    fallthrough_address: Optional[int],
) -> R2BlockInfoIn:
    """Constructs a basic block from a list of opcodes and next block address.
    Args:
        ops: The list of opcodes to include in the block.
        fallthrough_address: The address of the fallthrough block (if any).
    Returns:
        A block metadata dictionary without jump and optional fail fields.
    """
    def _compute_block_size(ops: list[R2OpcodeInfoIn]) -> int:
        if len(ops) == 0:
            return 0
        last_addr = get_address(ops[-1])
        instr_size = ops[-1].get("size", 0)
        min_bound = get_address(ops[0])
        max_bound = last_addr + instr_size
        return max(0, max_bound - min_bound)

    block_address = get_address(ops[0])
    out: R2BlockInfoIn = {
        "addr": block_address,
        "size": _compute_block_size(ops),
        "ops": ops,
    }
    if not is_address_placeholder(fallthrough_address):
        out["fail"] = fallthrough_address  # fallthrough after call
    return out

def split_block_on_calls(block: R2BlockInfoIn) -> list[R2BlockInfoIn]:
    """Splits a block into multiple blocks based on call instructions."""
    ops = block["ops"]
    if len(ops) == 0:
        return [block]
    
    split_blocks: list[R2BlockInfoIn] = []
    segment_start = 0
    segment_end = 0
    
    # 1. Head: segments terminating with calls
    for index, op in enumerate(ops):
        if not is_call_instruction(op):
            continue
        # Found a call instruction, split the block here
        segment_end = index + 1
        tail_ops = ops[segment_start:segment_end]
        # Fallthrough is the address of the next instruction if any
        if segment_end < len(ops):
            next_op = ops[segment_end]
            next_addr = get_address(next_op)
        else:
            # Function ends on a call instruction, check if the original block
            # had a fallthrough address
            orig_fail = block.get("fail")
            if not is_address_placeholder(orig_fail):
                next_addr = orig_fail
            else:
                # No fallthrough address, so the CFG ends here
                next_addr = None
        
        new_block = make_fallthrough_block(tail_ops, next_addr)
        split_blocks.append(new_block)
        segment_start = segment_end
    
    # If there were no calls, return the original block
    if len(split_blocks) == 0:
        return [block]
        
    # 2. Tail: remaining ops after last call, if any
    if segment_start < len(ops):
        tail_ops = ops[segment_start:]
        new_block = make_fallthrough_block(tail_ops, None)
        # Preserve original jump/fail fields on tail
        if not is_address_placeholder(block.get("jump")):
            new_block["jump"] = block.get("jump")
        if not is_address_placeholder(block.get("fail")):
            new_block["fail"] = block.get("fail")
        split_blocks.append(new_block)
            
    return split_blocks
    

class BlockProcessingResult(TypedDict):
    block_address: int
    split_on_calls: bool
    num_calls: int
    successor_addresses: set[int]

def process_block(block: R2BlockInfoIn, split_on_calls: bool=True
                  ) -> list[BlockProcessingResult]:
    """Processes a block and returns a list of BlockProcessingResult objects.
    Args:
        block: The block to process.
        split_on_calls: Whether to split the block on call instructions.
            Defaults to True.
    Returns:
        A list of BlockProcessingResult objects with the following fields:
        - block_address: the starting address of the block.
        - split_on_calls: whether the block was split on call instructions.
            This means that the maximum number of calls per block is 1.
        - num_calls: number of call instructions inside the block.
        - successor_addresses: A set of successor addresses of the block.
        The list may be greater than 1 if the block was split on calls.
    """
    results: list[BlockProcessingResult] = []
    
    if split_on_calls:
        split_blocks = split_block_on_calls(block)
        for block_data in split_blocks:
            result = BlockProcessingResult(
                block_address=get_address(block_data),
                split_on_calls=True,
                num_calls=1 if is_block_call_terminated(block_data) else 0,
                successor_addresses=get_block_successor_addresses(block_data)
            )
            results.append(result)
    else:
        num_calls = 0
        for op in block["ops"]:
            if is_call_instruction(op):
                num_calls += 1
            
        result = BlockProcessingResult(
            block_address=get_address(block),
            split_on_calls=False,
            num_calls=num_calls,
            successor_addresses=get_block_successor_addresses(block)
        )
        results.append(result)

    return results



class FunctionProcessingResult(TypedDict):
    """The data necessary to generate the machoke hash of a functinon.
    Fields:
        block_addresses_with_call: A set of block addresses that end with a
            call instruction.
        successor_addresses_map: A dictionary mapping block addresses to an
            ordered list of successor addresses. Note that the successor
            addresses falling outside the function should be ignored, as they
            are not part of the function's CFG.
        address_to_index: A dictionary mapping block addresses to their index.
    """
    block_addresses_with_call: dict[int, int]  # address -> num_calls
    successor_addresses_map: dict[int, list[int]]
    address_to_index: dict[int, int]

def process_blocks(blocks: list[R2BlockInfoIn], split_on_calls: bool=True
                   ) -> FunctionProcessingResult:
    block_addresses_with_call: dict[int, int] = {}
    successor_addresses_map: dict[int, list[int]] = {}
    block_addresses = set()
    for block in blocks:
        results = process_block(block, split_on_calls=split_on_calls)
        for result in results:
            block_address = result["block_address"]
            num_calls = result["num_calls"]
            successors = result["successor_addresses"]
            if num_calls > 0: 
                if split_on_calls:
                    block_addresses_with_call[block_address] = 1
                else:
                    block_addresses_with_call[block_address] = num_calls
                
            successor_addresses_map[block_address] = sorted(successors)
            block_addresses.add(block_address)
    
    block_addresses = sorted(block_addresses)
    address_to_index = OrderedDict((address, index) for index, address 
                                  in enumerate(block_addresses, start=1))
    
    return FunctionProcessingResult(
        block_addresses_with_call=block_addresses_with_call,
        successor_addresses_map=successor_addresses_map,
        address_to_index=address_to_index,
    )
    
def get_word_from_block_address(block_address: int,
                                block_addresses_with_call: dict[int, int],
                                successor_addresses_map: dict[int, list[int]],
                                address_to_index: dict[int, int]) -> str:
    """Returns the machoke word for a block address."""
    block_index = address_to_index[block_address]
    word = f"{block_index}:"
    tokens: list[str] = []
    if block_address in block_addresses_with_call.keys():
        calls_signature = ",".join(
            ["c"] * block_addresses_with_call[block_address])
        tokens.append(calls_signature)
    successor_addresses = successor_addresses_map[block_address]
    successor_indexes = [address_to_index[address] 
                         for address in successor_addresses 
                         if address in address_to_index.keys()]
    tokens.extend(str(index) for index in successor_indexes)
    word += ','.join(tokens) + ";"
    return word

def fcode_to_machoke_line(fcode: R2CodeInfoIn, 
                          split_on_calls: bool=True) -> str:
    """Converts r2 function code metadata (agfj) to a machoke-encoded line."""
    function_data = process_blocks(fcode["blocks"], 
                                   split_on_calls=split_on_calls)
    block_addresses_with_call = function_data["block_addresses_with_call"]
    successor_addresses_map = function_data["successor_addresses_map"]
    address_to_index = function_data["address_to_index"]
    block_addresses = address_to_index.keys()
    words: list[str] = []
    for block_addr in block_addresses:
        word = get_word_from_block_address(block_addr, 
                                           block_addresses_with_call,
                                           successor_addresses_map,
                                           address_to_index)
        words.append(word)
    return "".join(words)

def line_to_machoke_hash(line: str, ensure_length: bool = False) -> HexStr:
    """Returns the machoke hash of a line."""
    murmur_value = mmh3.hash(line) & 0xFFFFFFFF # make it positive
    if ensure_length:
        digest = f"{murmur_value:08x}" # ensure length is 8 (i.e. 4 bytes)
    else:
        digest = f"{murmur_value:x}"   # no leading zeroes
    return HexStr(digest)

def fcode_to_machoke_hash(fcode: R2CodeInfoIn,
                          ensure_length: bool = True,
                          split_on_calls: bool = True) -> HexStr:
    """Returns the machoke hash of a function."""
    line = fcode_to_machoke_line(fcode, split_on_calls=split_on_calls)
    return line_to_machoke_hash(line, ensure_length)
