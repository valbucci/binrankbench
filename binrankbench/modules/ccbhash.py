"""CCBHash: composite fuzzy hash over 13 weighted CFG, byte, and call-graph features."""

import bisect
import itertools
import math
from collections import Counter, deque
from typing import Any, Sequence, Optional, Literal, Dict, List, Tuple

import numpy as np
from dataclasses import dataclass, asdict
from hashlib import blake2b

from binrankbench.common.hex import HexStr, HexValue, HexInt
from binrankbench.common.utils import get_address, is_address_placeholder
from binrankbench.common.types import (R2CodeInfoIn, BIN2ML_CFG, R2ZignatureIn, 
                                   R2CallGraph, R2FunctionInfoIn)
from binrankbench.common.logging import LOGGER as base_logger

logger = base_logger.getChild("ccbhash")

# Extraction Modes / Parameters
ExtractionMode = Literal["hashes", "features"]
# Extension for DB files containing function ccbhashes
HASHES_EXT = "_ccbhash.csv"
# Extension for DB files containing encoded function features
FEATURES_EXT = "_ccbhash-features.csv"


# Size of the hash resulting from each function's feature
SUBHASH_SIZES = { # attribute_name -> hash_size
    'name': 4, 'cfg': 4, 'call_graph': 4, 'opcodes': 4, 'var_args': 4, 
    'var_locals': 4, 'ninstructions': 2, 'indegree': 1, 'outdegree': 1, 
    'nvars': 1, 'cc': 1, 'nblocks': 1, 'stackframe': 1
}

# CCBHash weights for each function feature.
ATTRIBUTE_WEIGHTS = {  # attribute_name -> similarity_score_weight
    'opcodes': 0.25, 'cfg': 0.16, 'cc': 0.15, 'outdegree': 0.09, 
    'ninstructions': 0.07, 'call_graph': 0.06, 'var_args': 0.04, 
    'var_locals': 0.04, 'nvars': 0.04, 'nblocks': 0.04, 'indegree': 0.03, 
    'stackframe': 0.02, 'name': 0.01
}

# Order subhashes first by weight (descending), then by size and by name
SUBHASH_ORDER = sorted(
    ATTRIBUTE_WEIGHTS.keys(),
    key=lambda k: (-ATTRIBUTE_WEIGHTS[k], SUBHASH_SIZES[k], k)
)

# CCBHash integer features quantiles for hashing
QUANTILES = {
        'ninstructions': [*range(8, 40), *range(41, 80, 2), *range(81, 160, 3), 
                          *range(161, 320, 4), *range(321, 1000, 5)],
        'indegree': [1, 2, 3, 4, 5, 6, 7, 8, 10, 13, 17, 22, 28, 35, 43],
        'outdegree': [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 16, 19, 23, 28],
        'nvars': [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 16, 19, 23, 28],
        'cc': [1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 16, 20, 25, 31],
        'nblocks': [1, 2, 3, 4, 5, 6, 7, 9, 12, 16, 21, 27, 34, 42, 51],
        'stackframe': 
            [1, 4, 8, 12, 16, 20, 24, 28, 40, 56, 80, 120, 200, 360, 620]
}

HASH_BOUNDARIES = [0, *itertools.accumulate([SUBHASH_SIZES[attr] 
                                             for attr in SUBHASH_ORDER])]
ALIGNED_WEIGHTS = [ATTRIBUTE_WEIGHTS[attr] for attr in SUBHASH_ORDER]


#region HELPERS

#region GENERIC

BlockEdges = dict[str, list[str]]       # block_offset -> output_offsets
BlockIndexes = dict[str, str]           # block_offset -> block_index
FunctionImports = dict[str, list[str]]  # func_name -> import_names
FunctionIndexes = dict[str, str]        # func_name -> func_index
CallGraphDict = dict[str, list[str]]    # func_name -> imports


def order_by_frequency(sequence: Sequence) -> tuple:
    """
    Removes duplicate elements in a sequence and returns them in a list,
    sorted first by frequency (descending) and then by value (ascending).
    """
    if len(sequence) == 0:
        return tuple()
    # Count frequencies
    counter = Counter(sequence)
    # Sort by frequency (descending) and then by value (ascending)
    sorted_items = sorted(counter.items(), 
                         key=lambda x: (-x[1], x[0]))
    # Extract unique elements in order
    unique_elements, _ = zip(*sorted_items)
    return unique_elements


def append_to_lists_dict(key, value, lists_dict: dict[str, list]) -> None:
    try:
        lists_dict[key].append(value)
    except KeyError:
        lists_dict[key] = [ value ]
        
        
def encode_sequence(sequence: Sequence) -> str:
    """
    Returns the given sequence converted to strings sorted in ascending order by 
    count, and concatenated with a separator.
    """
    ordered_values = order_by_frequency(sequence)
    ordered_values = map(str, ordered_values)
    return ';'.join(ordered_values)
        

def encode_graph(graph_edges: dict[str, list[str]], 
                 node_indexes: dict[str, str], is_cfg=False) -> str:
    """
    Encodes a graph using Machoc-like notation.
    
    For call graphs (is_cfg=False), uses dictionary insertion order to preserve
    the traversal order. For CFGs (is_cfg=True), sorts nodes by index.
    
    Args:
        graph_edges: Dictionary mapping node names/offsets to lists of outgoing nodes
        node_indexes: Dictionary mapping node names/offsets to their index strings
        is_cfg: Whether this is a CFG (True) or call graph (False)
        
    Returns:
        String encoding of the graph in Machoc-like notation
    """
    graph_parts = []
    
    if is_cfg:
        index_to_offset = {idx: offset for offset, idx in node_indexes.items()}
        sorted_indices = sorted(index_to_offset.keys())
        nodes_to_process = [(idx, index_to_offset[idx]) for idx in sorted_indices]
        
        for node_index, node_offset in nodes_to_process:
            if node_offset not in graph_edges:
                continue
            
            out_node_indexes = []
            for out_node in graph_edges[node_offset]:
                try:
                    out_node_indexes.append(node_indexes[out_node])
                except KeyError:
                    # Output node is not in the function (happens with Radare2).
                    # This can be safely ignored - the edge is simply not included.
                    continue
            
            if out_node_indexes:
                graph_parts.append(f"{node_index}:{','.join(out_node_indexes)};")
            else:
                graph_parts.append(f"{node_index}:;")
    else:
        for func_name, outputs in graph_edges.items():
            node_index = node_indexes.get(func_name)
            if node_index is None:
                continue
            
            out_node_indexes = []
            for out_node in outputs:
                try:
                    out_node_indexes.append(node_indexes[out_node])
                except KeyError:
                    # Output node is not in the function (happens with Radare2).
                    # This can be safely ignored - the edge is simply not included.
                    continue
            
            if out_node_indexes:
                graph_parts.append(f"{node_index}:{','.join(out_node_indexes)};")
            else:
                graph_parts.append(f"{node_index}:;")
    
    return ''.join(graph_parts)


#endregion GENERIC


#region CALL GRAPH

def global_call_graph_to_outputs(global_call_graph: R2CallGraph
                              ) -> CallGraphDict:
    global_outputs = {}
    for func in global_call_graph:
        func_name = func["name"]
        func_imports = func["imports"]
        global_outputs[func_name] = func_imports
    return global_outputs


def get_func_call_graph(func_name: str, global_call_graph: CallGraphDict
                        ) -> tuple[FunctionImports, FunctionIndexes]:
    func_call_graph = {}
    func_indexes = {}
    current_index = 0
    todo_func_names = [func_name]
    done_func_names = []
    while len(todo_func_names) > 0:
        # Get current function data from todo list
        current_name = todo_func_names.pop(0)
        if current_name in done_func_names:
            continue    # Already processed this function
        else:
            done_func_names.append(current_name)
        
        str_index = str(current_index)
        func_indexes[str_index] = current_name
        current_index += 1
        
        imports = global_call_graph.get(current_name, [])
        func_call_graph[current_name] = imports
        # Process all outgoing references next
        todo_func_names.extend(imports)
    
    return func_call_graph, func_indexes


def outputs_to_inputs(global_outputs: CallGraphDict
                          ) -> dict[str, list[str]]:
    global_inputs = {}
    for func_name, out_refs in global_outputs.items():
        for ref_name in out_refs:
            append_to_lists_dict(ref_name, func_name, global_inputs)
        
    return global_inputs


def calculate_degrees(global_refs: CallGraphDict) -> dict[str, int]:
    degrees = {}
    for func_name, refs in global_refs.items():
        degrees[func_name] = len(refs)
    return degrees


def call_graph_to_features(global_call_graph: R2CallGraph):
    # Generate the basic call graph dictionaries.
    outputs = global_call_graph_to_outputs(global_call_graph)
    outdegrees = calculate_degrees(outputs)
    inputs = outputs_to_inputs(outputs)
    indegrees = calculate_degrees(inputs)
    
    call_graph_features = {}
    
    # Process each function that appears in outputs.
    for func_name in outputs.keys():
        f_out_refs = outputs.get(func_name, [])
        f_in_refs = inputs.get(func_name, [])
        f_outdegree = outdegrees.get(func_name, 0)
        f_indegree = indegrees.get(func_name, 0)
        
        # Compute "oo" and "io" by iterating over the function's outputs.
        f_oo = sum(outdegrees.get(ref, 0) for ref in f_out_refs)
        f_io = sum(indegrees.get(ref, 0) for ref in f_out_refs)
        
        # Compute "oi" and "ii" by iterating over the function's inputs.
        f_oi = sum(outdegrees.get(ref, 0) for ref in f_in_refs)
        f_ii = sum(indegrees.get(ref, 0) for ref in f_in_refs)
        
        # Compute and encode call graph to normalised string
        f_adjacency = encode_graph(
            *extract_call_graph(func_name, global_call_graph))
        
        # Find the function info in the global call graph
        func_info = next((f for f in global_call_graph
                          if f["name"] == func_name), None)
        f_nargs = None
        f_nlocals = None
        f_nvars = None
        if func_info:
            f_nargs = func_info.get("nargs")
            f_nlocals = func_info.get("nlocals")
            if f_nargs is not None and f_nlocals is not None:
                f_nvars = f_nargs + f_nlocals
            
        call_graph_features[func_name] = {
            'outdegree': f_outdegree,
            'indegree': f_indegree,
            'oo': f_oo,
            'io': f_io,
            'oi': f_oi,
            'ii': f_ii,
            'cg_adjacency': f_adjacency,
            'nvars': f_nvars,
            'nargs': f_nargs,
            'nlocals': f_nlocals
        }
    
    return call_graph_features


def extract_call_graph(func_name: str, global_call_graph: R2CallGraph
                       ) -> tuple[FunctionImports, FunctionIndexes]:
    """
    Extracts the function's call graph by traversing the global call graph.
    
    Uses BFS traversal order and preserves import order from the global call graph.
    
    Args:
        func_name (str): The name of the function to be analysed.
        global_call_graph (list): List of functions with callgraph 
            information returned by r2.cmdj("agCj").
        
    Returns:
        dict[str, list]: The function names mapped to their imports.
        dict[str, str]: The function names mapped to their index relative to
            the given function.
    """
    if not global_call_graph:
        return {}, {}
    
    func_lookup = {}
    for func in global_call_graph:
        if func['name'] not in func_lookup:
            func_lookup[func['name']] = func
    
    func_call_graph: FunctionImports = {}
    func_indexes: FunctionIndexes = {}
    queue = deque([func_name])
    current_index = 0
    
    while queue:
        current_func = queue.popleft()
        func_indexes[current_func] = str(current_index)
        current_index += 1
        
        function = func_lookup.get(current_func)
        if function is None:
            continue
        
        if current_func not in func_call_graph:
            func_call_graph[current_func] = []
        
        imports = function.get('imports', [])
        for import_name in imports:
            if import_name not in func_call_graph[current_func]:
                func_call_graph[current_func].append(import_name)
                if import_name not in queue:
                    queue.append(import_name)
            
    return func_call_graph, func_indexes


#endregion CALL GRAPH


#region CFG

def get_bb_call_indexes(edges: BlockEdges, indexes: BlockIndexes) -> list[str]:
    """Returns the basic block indexes containing a call instruction."""
    bb_call_indexes = set()
    for block_offset, next_blocks in edges.items():
        for next_block in next_blocks:
            if next_block not in indexes.values():
                # Block at current offset references a non-block
                if block_offset in indexes:
                    bb_call_indexes.add(indexes[block_offset])
                break
    return list(bb_call_indexes)


def cfg_to_features(func_code: BIN2ML_CFG) -> dict:
    features = {}
    for entry in func_code:
        func = entry[0]
        func_cfg = extract_cfg(func)
        
        func_features = {}
        func_features["name"] = func["name"]
        func_features["stackframe"] = func["stack"]
        func_features["ninstr"] = func["ninstr"]
        func_features["instr_types"] = encode_sequence(
            extract_instruction_types(func))
        func_features["cfg_adjacency"] = encode_graph(*func_cfg, is_cfg=True)
        func_features["bb_outrefs"] = encode_sequence(
            get_bb_call_indexes(*func_cfg))
        
        # Add missing fields for ControlFlowFeatures
        func_features["bbsum"] = func.get("bbsum")  # Basic blocks checksum
        func_features["cc"] = func.get("cc")  # Cyclomatic complexity
        func_features["ebbs"] = func.get("ebbs")  # Number of entry basic blocks
        func_features["edges"] = func.get("edges")  # Number of edges
        func_features["nbbs"] = func.get("nbbs")  # Number of basic blocks
        
        func_addr = get_address(func)
        features[func_addr] = func_features
        
    return features


def extract_cfg(func_code: R2CodeInfoIn) -> tuple[BlockEdges, BlockIndexes]:
    """
    Extracts a control flow graph (CFG) from the given function code.

    Args:
        func_code (list): List of CFG basic blocks within a function
            returned by r2.cmdj("agj").
    
    Returns:
        dict[str, list]: The block offsets mapped to the list offsets of 
            their successive blocks.
        dict[str, str]: The block index relative to the given function 
            mapped to its offset.
    """
    # First, collect all blocks and sort them by address
    blocks = sorted(func_code["blocks"], key=lambda b: get_address(b))
    
    # Assign indexes in order of sorted offsets
    cfg_indexes: BlockIndexes = {
        str(get_address(block)): str(i) for i, block in enumerate(blocks)
    }
    
    # Build edges with consistent ordering
    cfg_edges: BlockEdges = {}
    for block in blocks:
        offset = str(get_address(block))
        edges = []
        # Add fail edge if it exists
        if "fail" in block and not is_address_placeholder(block["fail"]):
            fail_block_addr = str(block["fail"])
            edges.append(fail_block_addr)
        # Add jump edge if it exists
        if "jump" in block and not is_address_placeholder(block["jump"]):
            jump_block_addr = str(block["jump"])
            # Sort edges to ensure consistent ordering
            bisect.insort(edges, jump_block_addr)
        cfg_edges[offset] = edges
            
    return cfg_edges, cfg_indexes


def extract_instruction_types(func_code: R2CodeInfoIn, 
                              simplified=True) -> list[str]:
    """
    Extract the sequence of simplified opcode instruction types.

    Args:
        func_code (list): List of CFG basic blocks within a function
            returned by r2.cmdj("agj").
        simplified (bool): If True removes details from variations of 
            "cmp", "jmp", "call", "push" instructions. Defaults to True.
            
    Returns:
        list[str]: The sequence of instructions types from all blocks contained
            in the given function.
    """
    
    def simplify_instruction(ins_type: str) -> str:
        """Simplifies an opcode instruction type returned by r2."""
        for keyword in ["cmp", "jmp", "call", "push"]:
            if keyword in ins_type:
                return keyword
        return ins_type
    
    instructions = []
    # Sort blocks by address to ensure consistent ordering
    blocks = sorted(func_code["blocks"], key=lambda b: get_address(b))
    for block in blocks:
        # Sort instructions by address to ensure consistent ordering
        ops = sorted(block["ops"], key=lambda op: get_address(op))
        for instruction in ops:
            ins_type = instruction.get("type", None)
            if ins_type is None or ins_type == 'nop': continue
            if simplified: ins_type = simplify_instruction(ins_type)
            instructions.append(ins_type)
            
    return instructions


def extract_variable_types(func_zig: R2ZignatureIn
                           ) -> tuple[list[str], list[str]]:
    """
    Extracts the list of data types (e.g. int32_t) from a function and 
    splits it in a tuple (arguments and locals).
    
    Args:
        func_zigs (dict): information about the function variables, returned 
            by r2.cmdj("zj").
            
    Returns:
        list[str]: The types of arguments expected by the given function.
        list[str]: The types of local variables used by the given function.
    """
    type_args =  []
    type_locals = []
    
    for var in func_zig["vars"]:
        if var["isarg"]:
            type_args.append(var["type"])
        else:
            type_locals.append(var["type"])
            
    return type_args, type_locals


#endregion CFG


#endregion HELPERS


#region CCBHash Wrapper

class CCBHash(HexStr):
    
    def __new__(cls, digest: HexValue, skip_validation=False):
        if isinstance(digest, cls):
            return digest  # Already instantiated, avoid re-validation
        if not skip_validation:
            cls.validate_digest(digest)
        return super().__new__(cls, digest)
    
    def __eq__(self, other):
        return str(self) == str(other)

    def __repr__(self):
        return f"{type(self)}({super().__repr__()})"
    
    def __hash__(self):
        return hash(self.__str__())
    
    @classmethod
    def validate_type(cls, digest: Any):
        try:
            HexStr(digest)
        except ValueError:
            raise TypeError(
                f"Invalid {cls} digest {digest!r}: expected HexValue instance, "
                f"but got {type(digest)} instead. ")
    
    @classmethod
    def validate_length(cls, digest: HexValue, expected_length: int):
        digest = HexStr(digest)
        if len(digest) != expected_length:
            # Invalid hash size
            raise ValueError(
                f"Invalid {cls} digest '{digest}': expected length of "
                f"{expected_length}, but got {len(digest)} instead. ")
            
    @classmethod
    def validate_hexstr(cls, digest: HexValue):
        digest = HexStr(digest)
        charset = set("0123456789ABCDEF")
        non_hex_charset = set(digest).difference(charset)
        if len(non_hex_charset) > 0:
            # Invalid characters
            raise ValueError(
                f"Invalid {cls} digest `{digest}`: contains unexpected "
                f"characters {non_hex_charset}.")

    @classmethod
    def validate_digest(cls, digest: HexValue) -> None:
        """Parses a CCBHash digest and raises an exception if invalid"""
        cls.validate_type(digest)
        cls.validate_length(digest, sum(SUBHASH_SIZES.values()))
        cls.validate_hexstr(digest)
        
    @classmethod
    def split_digest(cls, digest: HexValue) -> list[HexStr]:
        digest = HexStr(digest)
        return [HexStr(digest[start:end]) 
                for start, end in zip(HASH_BOUNDARIES, HASH_BOUNDARIES[1:])]

    @property
    def hash_list(self) -> list[HexStr]:
        return self.split_digest(self)

    @property
    def hash_dict(self) -> dict[str, HexStr]:
        return dict(zip(SUBHASH_ORDER, self.hash_list))

    @property
    def hash_vector(self) -> list[HexInt]:
        return list(map(lambda sub_hash: HexInt(sub_hash), self.hash_list))

    @property
    def hash_vector_dict(self) -> dict[str, HexInt]:
        """Returns a dictionary mapping subhashes to their integer values."""
        return dict(zip(SUBHASH_ORDER, self.hash_vector))

    def to_numpy(self) -> np.ndarray:
        return np.array(self.hash_vector, dtype=np.int64)

    @staticmethod
    def numpy_similarity(vec_a: np.ndarray, vec_b: np.ndarray, aligned_weights: np.ndarray) -> float:
        return float(np.dot(aligned_weights, vec_a == vec_b))

    @staticmethod
    def numpy_similarity_batch(mat_a: np.ndarray, mat_b: np.ndarray, aligned_weights: np.ndarray) -> np.ndarray:
        """Vectorized similarity for N pairs. mat_a, mat_b: (N, K) int64; returns (N,) float64."""
        return (mat_a == mat_b) @ aligned_weights

    @classmethod
    def hash_similarity(cls, hash1: HexValue, hash2: HexValue, 
                        precision: Optional[int] = None, 
                        aligned_weights=ALIGNED_WEIGHTS) -> float:
        """Compares two hashes and returns their similarity score"""
        splits1 = cls.split_digest(hash1)
        splits2 = cls.split_digest(hash2)
        sim = sum(
            weight for sub1, sub2, weight 
            in zip(splits1, splits2, aligned_weights) 
            if sub1 == sub2
        )
        return sim if precision is None else round(sim, ndigits=precision)
    
    @classmethod
    def hash_difference(cls, hash1: HexValue, hash2: HexValue, 
                        precision: Optional[int] = None, 
                        aligned_weights=ALIGNED_WEIGHTS) -> float:
        return 1 - cls.hash_similarity(hash1, hash2, precision, aligned_weights)

    def similarity(self, other: HexValue) -> float:
        return self.hash_similarity(self, other)
    
    def difference(self, other: HexValue) -> float:
        return self.hash_difference(self, other)

#endregion CCBHash Wrapper


#region CCBHash Features

@dataclass(slots=True)
class CCBHashFeatures:
    """Dataclass for storing function features used to generate its CCBHash."""
    
    # Instance attributes
    name: str
    cfg: str
    call_graph: str
    opcodes: str
    var_args: str
    var_locals: str
    ninstructions: int
    indegree: int
    outdegree: int
    nvars: int
    cc: int
    nblocks: int
    stackframe: int
    _ccbhash: Optional[CCBHash] = None
    
    def _setup_ccbhash(self):
        """Calculate CCBHash digest if not provided"""
        if self._ccbhash is None:
            # Generate CCBHash from features
            self._ccbhash = CCBHash(self.hash_digest)
        elif not isinstance(self._ccbhash, CCBHash):
            # Make sure it's parsed as a CCBHash object
            self._ccbhash = CCBHash(self._ccbhash)

    def __post_init__(self):
        self._setup_ccbhash()
        
    def to_dict(self, complete=True) -> dict:
        """Converts the CCBHashFeatures object to a dictionary.

        Args:
            complete (bool): If True, returns all features. 
                             If False, returns only name and CCBHash digest.

        Returns:
            dict: The dictionary representation of the CCBHashFeatures object.
        """

        if complete:
            # All features available for generating CCBHash
            # - clean up the dataclass structure
            def dict_factory(items) -> dict:
                # Rename _ccbhash to ccbhash
                return {("ccbhash" if key == "_ccbhash" 
                        else key): value for key, value in items}

            return asdict(self, dict_factory=dict_factory)

        else:
            # Only name and CCBHash digest
            return {"name": self.name, "ccbhash": self.ccbhash}
    
    @classmethod
    def from_dict(cls, data: dict[str, str]) -> "CCBHashFeatures":
        return cls(data["name"], data["cfg"], data["call_graph"], 
                   data["opcodes"], data["var_args"], data["var_locals"], 
                   int(data["ninstructions"]), int(data["indegree"]), 
                   int(data["outdegree"]), int(data["nvars"]), int(data["cc"]), 
                   int(data["nblocks"]), int(data["stackframe"]), 
                   data.get("ccbhash", None)) # type: ignore
    
    #region --- HASHING ---
    #region -- Utils --
    
    @classmethod
    def hash_from_string(cls, value: str) -> HexStr:
        """Hashes a string value with collision-resistant hashing.

        Args:
            value (str): The input string to hash.

        Returns:
            HexStr: A hexadecimal string representation of the hash.
        """
        # Leave digest_size=2 or will be incompatible with previous CCBHashes
        return HexStr(blake2b(str.encode(value), digest_size=2).hexdigest())
    
    
    @staticmethod
    def dec_to_hex(decimal: int, max_value: int) -> str:
        """Returns converted decimal to hex string with padding"""
        padding = int(math.log(max_value + 1, 16)) + 2
        return f"{decimal:#0{padding}x}"[2:]
    
    @classmethod
    def hash_from_quantiles(cls, value: int, quantiles: list[int]) -> HexStr:
        """
        Hashes an integer value to a single-digit hexadecimal string based on 
        quantiles.

        Args:
            value (int): The input integer to hash.
            quantiles (list[int]): A list of integer quantiles.

        Returns:
            HexStr: A hexadecimal string representation of the hash.

        Raises:
            ValueError: If the len(quantiles) + 1 is not divisible by 16.
        """
        
        if (len(quantiles) + 1) % 16 != 0:
            raise ValueError(f"Cannot map value '{value}' to hexadecimal value"
                             f" using {len(quantiles)} quantile values.")
        for index, upper_bound in enumerate(quantiles):
            if value < upper_bound:
                return HexStr(cls.dec_to_hex(index, len(quantiles)))
        return HexStr(cls.dec_to_hex(len(quantiles), len(quantiles)))
    
    #endregion -- Utils --
    
    #region -- Properties --
    
    @property
    def name_hash(self) -> HexStr:
        return self.hash_from_string(self.name)
    
    @property
    def cfg_hash(self) -> HexStr:
        """Returns the hashed control flow graph (CFG)"""
        return self.hash_from_string(self.cfg)
    
    @property
    def call_graph_hash(self) -> HexStr:
        """Returns the hashed function call graph"""
        return self.hash_from_string(self.call_graph)
    
    @property
    def opcodes_hash(self) -> HexStr:
        """Returns hashed instruction types ordered by count"""
        return self.hash_from_string(self.opcodes)
    
    @property
    def args_hash(self) -> HexStr:
        """Returns hashed argument variable types"""
        return self.hash_from_string(self.var_args)
    
    @property
    def locals_hash(self) -> HexStr:
        """Returns hashed local variable types"""
        return self.hash_from_string(self.var_locals)
    
    @property
    def ninstructions_hash(self) -> HexStr:
        """Returns the number of instructions hashed as one byte"""
        return self.hash_from_quantiles(self.ninstructions, 
                                        QUANTILES['ninstructions'])
    
    @property
    def indegree_hash(self) -> HexStr:
        """Returns the callgraph indegree value hashed as one nibble"""
        return self.hash_from_quantiles(self.indegree, QUANTILES['indegree'])
    
    @property
    def outdegree_hash(self) -> HexStr:
        """Returns the callgraph outdegree value hashed as one nibble"""
        return self.hash_from_quantiles(self.outdegree, QUANTILES['outdegree'])
    
    @property
    def nvars_hash(self) -> HexStr:
        """Returns the total amount of variables hashed as one nibble"""
        return self.hash_from_quantiles(self.nvars, QUANTILES['nvars'])
    
    @property
    def cc_hash(self) -> HexStr:
        """Returns the cyclomatic complexity hashed as one nibble"""
        return self.hash_from_quantiles(self.cc, QUANTILES['cc'])
    
    @property
    def nblocks_hash(self) -> HexStr:
        """Returns the number of blocks hashed as one nibble"""
        return self.hash_from_quantiles(self.nblocks, QUANTILES['nblocks'])
    
    @property
    def stackframe_hash(self) -> HexStr:
        """Returns the stackframe size hased as one nibble"""
        return self.hash_from_quantiles(self.stackframe, 
                                        QUANTILES['stackframe'])
        
    #endregion -- Properties --
    
    #region -- Hash --
    
    @property
    def hash_list(self) -> list[HexStr]:
        """Returns the hash as a list of hexadecimal strings."""
        if self._ccbhash is not None:
            return self._ccbhash.hash_list
        
        # Use SUBHASH_ORDER for consistent ordering of hash components
        subhash_dict = {
            'name': self.name_hash,
            'cfg': self.cfg_hash,
            'call_graph': self.call_graph_hash,
            'opcodes': self.opcodes_hash,
            'var_args': self.args_hash,
            'var_locals': self.locals_hash,
            'ninstructions': self.ninstructions_hash,
            'indegree': self.indegree_hash,
            'outdegree': self.outdegree_hash,
            'nvars': self.nvars_hash,
            'cc': self.cc_hash,
            'nblocks': self.nblocks_hash,
            'stackframe': self.stackframe_hash
        }
        
        return [subhash_dict[attr] for attr in SUBHASH_ORDER]

    @property
    def hash_vector(self) -> list[HexInt]:
        """Returns the hash as a vector of integers."""
        return list(self.ccbhash.hash_vector)

    @property
    def hash_digest(self) -> HexStr:
        """Returns the hash compressed in one hexadecimal string"""
        return HexStr(''.join(self.hash_list))
    
    @property
    def ccbhash(self) -> CCBHash:
        """Returns a CCBHash object generated from the function features"""
        self._setup_ccbhash()
        return self._ccbhash # type: ignore
    
    #endregion -- Hash --
    #endregion --- HASHING ---


#endregion CCBHash Features


#region CCBHash Builder

    
class CCBHashBuilder:
    
    logger = logger.getChild("CCBHashBuilder")
    
    @classmethod
    def encode_sequence(cls, sequence: Sequence[str]) -> str:
        """
        Returns the given sequence of strings sorted in ascending order by 
        count, and concatenated with a separator.
        """
        ordered_values = order_by_frequency(sequence)
        return ';'.join(ordered_values)

    @classmethod
    def encode_graph(cls, graph_edges: dict[str, list[str]], 
                     node_indexes: dict[str, str], is_cfg=False) -> str:
        """Encodes a graph using Machoc-like notation."""
        return encode_graph(graph_edges, node_indexes, is_cfg)
    
    @classmethod
    def filter_machoke_line(cls, machoke_line: str) -> str:
        """Filters a Machoke line to remove invalid nodes."""
        return machoke_line.replace('c,', '').replace('c', '')    
    
    
    @classmethod
    def build_features(cls, func_info: R2FunctionInfoIn, 
                       func_zig: R2ZignatureIn, func_code: R2CodeInfoIn, 
                       global_call_graph: R2CallGraph,
                       cfg_override: Optional[str] = None) -> tuple:
        
        if cfg_override is None:
            cls.logger.debug("Encoding CFG ...")
            cfg_str = cls.encode_graph(*extract_cfg(func_code), is_cfg=True)
        else:
            cls.logger.debug(f"Using CFG override: {cfg_override}")
            cfg_str = cfg_override
        
        cls.logger.debug("Encoding function call graph ...")
        call_graph_str = cls.encode_graph(*extract_call_graph(func_info['name'], 
                                          global_call_graph))
        
        cls.logger.debug("Encoding instructions ...")
        instr_types = cls.encode_sequence(extract_instruction_types(func_code))

        cls.logger.debug("Encoding arguments and local variables ...")
        var_args, var_locals = map(cls.encode_sequence, 
                                   extract_variable_types(func_zig))
        nvars = func_code.get('nargs', 0) + func_code.get('nlocals', 0)
        return (func_info["name"], cfg_str, call_graph_str, instr_types, 
                var_args, var_locals, func_info["ninstrs"], 
                func_info["indegree"], func_info["outdegree"], nvars, 
                func_info["cc"], func_info["nbbs"], func_info["stackframe"])
    
    @classmethod
    def build(cls, func_info: R2FunctionInfoIn, func_zig: R2ZignatureIn, 
              func_code: R2CodeInfoIn, global_call_graph: R2CallGraph
              ) -> CCBHashFeatures:
        """
        Extract features to generate a function's CCBHash from r2 data.

        Args:
            func_info (dict): Dictionary about the function information
                contained in the list elements returned by r2.cmdj("aflj"). 
            func_vars (dict): Dictionary about the function variables returned 
                by r2.cmdj("afvj").
            func_code (list): List of CFG basic blocks within a function
                returned by r2.cmdj("agj").
            global_callgraph (list): List of functions with callgraph 
                information returned by r2.cmdj("agCj").
            mode (str): The mode to use to encode the CFG.
            machoke_line (str): The Machoke line to use to encode the CFG.
        Returns:
            CCBHashFeatures: all features and CCBHash of the given function.
        """
        
        (func_name, cfg_str, call_graph_str, instr_types, var_args, var_locals, 
         ninstructions, indegree, outdegree, nvars, cc, nblocks, stackframe
         ) = cls.build_features(func_info, func_zig, func_code, 
                                global_call_graph)
        
        cls.logger.debug("Building CCBHash from encoded features ...")
        return CCBHashFeatures(func_name, cfg_str, call_graph_str, instr_types, 
                               var_args, var_locals, ninstructions, indegree, 
                               outdegree, nvars, cc, nblocks, stackframe)

#endregion CCBHash Builder
