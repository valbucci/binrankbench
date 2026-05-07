"""Function SimSearch (FSS): CFG-based SimHash in Original and Marcelli-weighted variants."""

import copy
from typing import Self, Iterator, Optional, Iterable, Literal
from functionsimsearch import FlowgraphWithInstructions as OFWI, \
                              SimHasher as OSH
from marcellisimsearch import FlowgraphWithInstructions as MFWI, \
                              SimHasher as MSH
from binrankbench.common.types import BIN2ML_CFG, R2CodeInfoIn
from binrankbench.common.utils import get_address
from binrankbench.common.hex import HexValue, hexvalue_to_int


FssMode = Literal["original", "marcelli"]


def split_disasm(disasm):
    fist_split = disasm.split()
    return tuple([token.rstrip(",") for token in fist_split])


def popcount(x):
    return bin(x).count("1")


def instructions_iterable_to_nested_tuple(instructions: Iterable):
    nested_list = []
    for block_addr, mnemonics_data in instructions:
        opcode_list = []
        for opcode in mnemonics_data:
            mnemonic = opcode[0]
            operands = tuple(opcode[1])
            opcode_list.append((mnemonic, operands))
        nested_list.append((block_addr, tuple(opcode_list)))
    return tuple(nested_list)


def instructions_dict_to_nested_tuple(instructions: dict):
    return instructions_iterable_to_nested_tuple(instructions.items())


def compute_hash(nodes, edges, instructions, mode: FssMode="original", 
                 marcelli_weights: Optional[dict[str, float]] = None, 
                 path_to_weights=""):
    if mode == "original":
        flowgraph = OFWI()
        hasher = OSH(path_to_weights)
    elif mode == "marcelli":
        if marcelli_weights is None:
            marcelli_weights = {"mnem_weight": 1., "graphlet_weight": 1., 
                                "immediate_weight": 1.}
        flowgraph = MFWI()
        hasher = MSH(**marcelli_weights)
    else:
        raise ValueError(f"Invalid mode: {mode}")
        
    for node in nodes:
        flowgraph.add_node(node)
    for edge in edges:
        flowgraph.add_edge(edge[0], edge[1])

    if isinstance(instructions, dict):
        instructions = instructions_dict_to_nested_tuple(instructions)
    for block_addr, mnemonics_data in instructions:
        flowgraph.add_instructions(int(block_addr), mnemonics_data)
    return hasher.calculate_hash(flowgraph)


def fcode_to_components(fcode_data: R2CodeInfoIn, use_graphlets = True, 
                        use_immediates = True, use_mnemonics = True
                        ) -> tuple[list, list, list]:
    json_blocks = fcode_data["blocks"]
    nodes = []
    edges = []
    instructions = []
    
    for index, block in enumerate(json_blocks):
        block_address = get_address(block)
        # Basic blocks
        nodes.append(block_address)
        
        # Flow graph edges
        if use_graphlets:
            jump = block.get("jump")
            if jump is not None:
                edges.append((block_address, jump))
            fail = block.get("fail")
            if fail is not None:
                edges.append((block_address, fail))
            if (fail is None or jump is None) and index < len(json_blocks) - 1:
                # Fallthrough edge to next block
                next_block = json_blocks[index + 1]
                next_address = get_address(next_block)
                edges.append((block_address, next_address))

        # Instructions
        if use_mnemonics:
            ops = block["ops"]
            mnemonics_data = []
            for op_data in ops:
                try:
                    disasm = op_data["disasm"]
                except KeyError:
                    # Sometimes this happens; Just continue 
                    continue
                if disasm is None:
                    # Disasm can be None for some instructions
                    continue
                disasm_tokens = split_disasm(disasm)
                mnemonic = disasm_tokens[0]
                if use_immediates:
                    operands = disasm_tokens[1:]
                else:
                    operands = []
                mnemonics_data.append((mnemonic, tuple(operands)))
            instructions.append((int(block_address), tuple(mnemonics_data)))
            
    return nodes, edges, instructions


def fcode_to_hash(fcode_data: R2CodeInfoIn, path_to_weights="", 
                  mode: FssMode="original", 
                  marcelli_weights: Optional[dict[str, float]] = None,
                  use_graphlets = True,
                  use_immediates = True,
                  use_mnemonics = True):
    nodes, edges, instructions = fcode_to_components(
        fcode_data, use_graphlets=use_graphlets, use_immediates=use_immediates, 
        use_mnemonics=use_mnemonics)

    return compute_hash(nodes, edges, instructions, 
                        path_to_weights=path_to_weights,
                        mode=mode,
                        marcelli_weights=marcelli_weights)


#region FSS WITH INTERMEDIATE REPRESENTATIONS
def simplify_instruction(ins_type: str) -> str:
        """Simplifies an opcode instruction type returned by r2."""
        for keyword in ["cmp", "jmp", "call", "push"]:
            if keyword in ins_type:
                return keyword
        return ins_type


def fcode_to_components_ir(fcode_data: R2CodeInfoIn, use_graphlets = True, 
                            use_immediates = True) -> tuple[list, list, list]:
    json_blocks = fcode_data["blocks"]
    nodes = []
    edges = []
    instructions = []
    
    for index, block in enumerate(json_blocks):
        block_address = get_address(block)
        # Basic blocks
        nodes.append(block_address)
        
        # Flow graph edges
        if use_graphlets:
            jump = block.get("jump")
            if jump is not None:
                edges.append((block_address, jump))
            fail = block.get("fail")
            if fail is not None:
                edges.append((block_address, fail))
            if (fail is None or jump is None) and index < len(json_blocks) - 1:
                # Fallthrough edge to next block
                next_block = json_blocks[index + 1]
                next_address = get_address(next_block)
                edges.append((block_address, next_address))

        # Instructions
        ops = block["ops"]
        mnemonics_data = []
        for op_data in ops:
            try:
                disasm = op_data["disasm"]
            except KeyError:
                # Sometimes this happens; Just continue 
                continue
            if disasm is None:
                # Disasm can be None for some instructions
                continue
            disasm_tokens = split_disasm(disasm)
            mnemonic = simplify_instruction(disasm_tokens[0])
            if use_immediates:
                operands = disasm_tokens[1:]
            else:
                operands = []
            mnemonics_data.append((mnemonic, tuple(operands)))
        instructions.append((int(block_address), tuple(mnemonics_data)))

    return nodes, edges, instructions


def fcode_to_hash_ir(fcode_data: R2CodeInfoIn, path_to_weights="", 
                     mode: FssMode="original", 
                     marcelli_weights: Optional[dict[str, float]] = None,
                     use_graphlets = True,
                     use_immediates = True):
    nodes, edges, instructions = fcode_to_components_ir(
        fcode_data, use_graphlets=use_graphlets, use_immediates=use_immediates)

    return compute_hash(nodes, edges, instructions, 
                        path_to_weights=path_to_weights,
                        mode=mode,
                        marcelli_weights=marcelli_weights)
#endregion FSS WITH INTERMEDIATE REPRESENTATIONS


class FunctionSimSearch:
    
    __slots__ = ("value",)
    
    def __init__(self, first: HexValue, second: HexValue):

        first = hexvalue_to_int(first)
        second = hexvalue_to_int(second)
        if not (self.check_bit_size(first, 64) and 
                self.check_bit_size(second, 64)):
            raise ValueError(
                "First and second must be 64 bits long, got %d and %d bits" 
                % (first.bit_length(), second.bit_length()))
        
        self.value = (first << 64) | second
        
    def __repr__(self):
        return f"FunctionSimSearch({self.first:#x}, {self.second:#x})"
    
    def __str__(self):
        return f"{self.value:032X}"

    def __bytes__(self):
        return self.as_bytes
        
    def __eq__(self, other):
        return self.value == other.value
    
    def __hash__(self):
        return self.value
    
    def __iter__(self):
        yield self.first
        yield self.second
    
    def __copy__(self) -> Self:
        return type(self)(self.first, self.second)

    def __deepcopy__(self, _) -> Self:
        return self.__copy__()

    def copy(self) -> Self:
        return copy.copy(self)
    
    @staticmethod
    def first_from_value(value: int):
        return value >> 64
    
    @staticmethod
    def second_from_value(value: int):
        return value & 0xFFFFFFFFFFFFFFFF
    
    @staticmethod
    def check_bit_size(value: int, bit_size: int) -> bool:
        return value.bit_length() <= bit_size
        
    @property
    def first(self):
        return self.first_from_value(self.value)
        
    @property
    def second(self):
        return self.second_from_value(self.value)
    
    @property
    def as_bytes(self):
        return self.value.to_bytes(16, "big")
    
    @classmethod
    def from_value(cls, value: int) -> Self:
        if not cls.check_bit_size(value, 128):
            raise ValueError("Value must be 128 bits long, got %d bits" 
                             % value.bit_length())
        return cls(cls.first_from_value(value), cls.second_from_value(value))
    
    @classmethod
    def fromhex(cls, hexstr: str) -> Self:
        return cls.from_value(int(hexstr, 16))
    
    @classmethod
    def fromhexpair(cls, first: str, second: str) -> Self:
        return cls(int(first, 16), int(second, 16))
    
    @classmethod
    def from_bytes(cls, bytes_: bytes) -> Self:
        return cls.from_value(
            int.from_bytes(bytes_, byteorder="big", signed=False))
    
    @classmethod
    def from_components(
        cls, nodes, edges, instructions, mode: FssMode="original", 
        marcelli_weights: Optional[dict[str, float]] = None, 
        path_to_weights=""
    ) -> Self:
        result = compute_hash(nodes, edges, instructions, mode, 
                              marcelli_weights, path_to_weights)
        return cls(result[0], result[1])
    
    @classmethod
    def from_fcode(cls, fcode_data: R2CodeInfoIn, path_to_weights="", 
                   mode: FssMode="original", 
                   marcelli_weights: Optional[dict[str, float]] = None,
                   use_graphlets = True,
                   use_immediates = True,
                   use_mnemonics = True,
                   ) -> Self:
        """
        Returns FSS hash from data extracted with radare2 command `agfj`.
        """
        result = fcode_to_hash(fcode_data, path_to_weights, mode, 
                               marcelli_weights, use_graphlets, use_immediates,
                               use_mnemonics)
        return cls(result[0], result[1])
    
    @classmethod
    def from_bin2ml_cfg(cls, bin2ml_cfg_data: BIN2ML_CFG, path_to_weights="", 
                        mode: FssMode="original", 
                        marcelli_weights: Optional[dict[str, float]] = None
                        ) -> Iterator[tuple[int, str, Self]]:
        """
        Iterates over CFG data extracted with bin2ml and yields the address, 
        name, and FSS hash for each function.
        """
        for (fcode_data,) in bin2ml_cfg_data:
            yield (
                get_address(fcode_data),
                fcode_data["name"],
                cls.from_fcode(fcode_data, path_to_weights, mode, 
                               marcelli_weights)
            )

    def hamming_distance(self, other) -> int:
        return popcount(self.value ^ other.value)

    def similarity(self, other, precision: Optional[int] = None) -> float:
        # Similarity score normalization. Since a similarity score of 50% is
        # the theoretical minimum for two different functions, 
        # we normalize 128-bit distance by 64 to cut off the lower 50%
        # and get a score between 0 and 1.
        sim = 64 - self.hamming_distance(other)
        sim = max(0, sim) / 64
        return sim if precision is None else round(sim, ndigits=precision)
