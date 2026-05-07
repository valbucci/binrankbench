"""TypedDict schemas for radare2-extracted binary analysis data (CFGs, call graphs, function info)."""

from typing import TypedDict, Optional, NotRequired, Union, Literal

from binrankbench.common.hex import HexOffset


JSONPrimitive = (None | bool | int | float | str)
JSONArray = list["JSONType"]
JSONObject = dict[str, "JSONType"]
JSONType = (JSONPrimitive | JSONArray | JSONObject)


#region BINARY STRUCTURE
# Basic blocks relationships (CFG edges and numeric index)
BlockOffset = HexOffset
BlockEdges = dict[BlockOffset, list[BlockOffset]] # basic block -> next blocks
BlockIndexes = dict[BlockOffset, str]             # basic block -> index in CFG

# Function relationships (Call graph edges and numeric index)
FunctionOffset = HexOffset
FunctionName = str
FunctionEdges = \
    dict[FunctionName, list[FunctionName]] # function name -> called functions
FunctionIndexes = dict[FunctionName, str]  # function name -> index in call graph
#endregion BINARY STRUCTURE


#region BIN2ML
BIN2ML_CFG = list[list["R2CodeInfoIn"]]         # agfj @@f
# TODO: Gemini, DGIS, BinKit, etc.
#endregion BIN2ML


#region TYPING UTILS

_HasOffset = Union["_R2FunctionInfoOffset", "_R2OpcodeInfoOffset", 
                   "_R2BlockInfoOffset", "_R2CodeInfoOffset", 
                   "_R2ZignatureOffset"]
_HasAddr = Union["_R2FunctionInfoAddr", "_R2OpcodeInfoAddr", 
                 "_R2BlockInfoAddr", "_R2CodeInfoAddr", 
                 "_R2ZignatureAddr"]
_HasOffsetOrAddr = Union[_HasOffset, _HasAddr]
#endregion TYPING UTILS


#region RADARE2
#region RADARE2 FUNCTIONS

#region  -- Function Info (afij) --
class _R2FunctionInfoOffset(TypedDict, total=True):
    offset: int
    name: str
    ninstrs: int
    nbbs: int
    indegree: int
    outdegree: int
    cc: int
    stackframe: int
    size: int
    nlocals: int
    nargs: int
    # Other attributes not used
    
class _R2FunctionInfoAddr(TypedDict, total=True):
    addr: int
    name: str
    ninstrs: int
    nbbs: int
    indegree: int
    outdegree: int
    cc: int
    stackframe: int
    size: int
    nlocals: int
    nargs: int
R2FunctionInfoIn = _R2FunctionInfoOffset | _R2FunctionInfoAddr
#endregion -- Function Info (afij) --


#region  -- Function Vars (afvj) --
class R2VarInfo(TypedDict, total=False):        # afvj ("regs", "sp", "bp")
    kind: str
    type: str
    # Other attributes not used

class R2FunctionVars(TypedDict, total=True):    # afvj
    reg: list[R2VarInfo]    # Register-based variables
    sp: list[R2VarInfo]     # Stack Pointer-based variables
    bp: list[R2VarInfo]     # Base Pointer-based variables

#endregion -- Function Vars (afvj) --


#region  -- Code Info (agfj) --
#region  --- Opcode Info ---
class R2OpcodeInfoReference(TypedDict, total=True):
    addr: int
    perm: Literal["r--", "-w-", "--x"]
    type: Literal["DATA", "CODE", "CALL", "STRN", "ICOD"] # Could be more (?)


class _R2OpcodeInfoOffset(TypedDict, total=True):      # agfj ("ops")
    offset: int
    size: int
    type: str
    
    bytes: str
    family: str
    disasm: str # disassembly
    opcode: str # pseudo-assembly
    esil: str
    
    jump: NotRequired[int] # radare2 <6.0.0
    fail: NotRequired[int] # radare2 <6.0.0
    ptr: NotRequired[Optional[int]]
    refs: NotRequired[Optional[list[R2OpcodeInfoReference]]]  # radare2 >=6.0.0
    xrefs: NotRequired[Optional[list[R2OpcodeInfoReference]]] # radare2 >=6.0.0
    # Other attributes not used


class _R2OpcodeInfoAddr(TypedDict, total=True):      # agfj ("ops")
    addr: int
    size: int
    type: str
    
    bytes: str
    family: str
    disasm: str # disassembly
    opcode: str # pseudo-assembly
    esil: str
    
    jump: NotRequired[int] # radare2 <6.0.0
    fail: NotRequired[int] # radare2 <6.0.0
    ptr: NotRequired[Optional[int]]
    refs: NotRequired[Optional[list[R2OpcodeInfoReference]]]  # radare2 >=6.0.0
    xrefs: NotRequired[Optional[list[R2OpcodeInfoReference]]] # radare2 >=6.0.0
    
    # Other attributes not used

R2OpcodeInfoIn = _R2OpcodeInfoOffset | _R2OpcodeInfoAddr
#endregion --- Opcode Info ---

#region  --- Block Info ---
class _R2BlockInfoOffset(TypedDict, total=True):       # agfj ("blocks")
    offset: int
    size: int
    jump: NotRequired[Optional[int]]
    fail: NotRequired[Optional[int]]
    ops: list[R2OpcodeInfoIn]

class _R2BlockInfoAddr(TypedDict, total=True):       # agfj ("blocks")
    addr: int
    size: int
    jump: NotRequired[Optional[int]]
    fail: NotRequired[Optional[int]]
    ops: list[R2OpcodeInfoIn]

R2BlockInfoIn = _R2BlockInfoOffset | _R2BlockInfoAddr
#endregion --- Block Info ---

#region  --- Code Info ---
class _R2CodeInfoOffset(TypedDict, total=True):        # agfj
    name: str
    nargs: int
    ninstr: int
    nlocals: int
    offset: int
    size: int
    stack: int
    type: str
    blocks: list[R2BlockInfoIn]

class _R2CodeInfoAddr(TypedDict, total=True):        # agfj
    addr: int
    name: str
    nargs: int
    ninstr: int
    nlocals: int
    offset: int
    size: int
    stack: int
    type: str
    blocks: list[R2BlockInfoIn]
    
R2CodeInfoIn = _R2CodeInfoOffset | _R2CodeInfoAddr
#endregion --- Code Info ---
#endregion -- Code Info (agfj) --

#region  -- Function Calls (agCj) --
class R2FunctionCalls(TypedDict, total=True):   # agCj (array members)
    name: str
    size: int
    imports: list[str]
    
R2CallGraph = list[R2FunctionCalls]             # agCj
R2FunctionList = list[R2FunctionInfoIn]         # aflj
#endregion -- Function Calls (agCj) --
#endregion RADARE2 FUNCTIONS


#region RADARE2 ZIGNATURES
class R2GraphZignature(TypedDict, total=True):  # zj ("graph")
    bbsum: int  # basic blocks checksum (?)
    cc: int     # cyclomatic complexity
    ebbs: int   # number of entry basic blocks
    edges: int
    nbbs: int   # number of basic blocks
    
    
class R2HashZignature(TypedDict, total=True):   # zj ("hash")
    bbhash: str # basic blocks hash
    
    
class R2VarsZignature(TypedDict, total=True):   # zj ("vars" array members)
    delta: int  # location difference with function address
    isarg: bool
    kind: str   # registry kind
    name: str
    type: str

#region  -- Zignature (zj) --
class _R2ZignatureOffset(TypedDict, total=True):       # zj (array members)
    offset: int
    name: str
    next: str   # following function name in binary
    types: str
    bytes: str
    mask: str
    collisions: list[str]   # colliding function names
    refs: list[str]     # output functions
    xrefs: list[str]    # input functions
    graph: R2GraphZignature
    hash: R2HashZignature
    vars: list[R2VarsZignature]

class _R2ZignatureAddr(TypedDict, total=True):       # zj (array members)
    addr: int
    name: str
    next: str   # following function name in binary
    types: str
    bytes: str
    mask: str
    collisions: list[str]   # colliding function names
    refs: list[str]     # output functions
    xrefs: list[str]    # input functions
    graph: R2GraphZignature
    hash: R2HashZignature
    vars: list[R2VarsZignature]

R2ZignatureIn = _R2ZignatureOffset | _R2ZignatureAddr
#endregion -- Zignature (zj) --
#endregion RADARE2 ZIGNATURES


#region RADARE2 BINARY INFO
class R2BinInfoCore(TypedDict, total=True):     # ij (core entry)
    block: int
    fd: int
    file: str
    format: str
    type: str
    iorw: bool
    mode: str
    humansz: str
    size: int
    
R2BinInfoBin = TypedDict("R2BinInfoBin", {      # ij (bin entry)
    'arch': str,
    'baddr': Optional[int],
    'binsz': int,
    'bintype': str,
    'bits': int,
    'canary': bool,
    'cc': str,
    'checksums': dict[str, str],
    'class': str,
    'cmp.sum': Optional[str],
    'compiled': str,
    'compiler': str,
    'crypto': bool,
    'dbg_file': str,
    'endian': str,
    'guid': str,
    'havecode': bool,
    'hdr.csum': Optional[int],
    'injprot': bool,
    'intrp': str,
    'laddr': int,
    'lang': Optional[str],
    'linenum': bool,
    'lsyms': bool,
    'machine': str,
    'nx': bool,
    'os': str,
    'overlay': Optional[bool],
    'pic': bool,
    'relocs': bool,
    'retguard': Optional[bool],
    'rpath': str,
    'sanitize': bool,
    'signed': Optional[bool],
    'static': bool,
    'stripped': bool,
    'subsys': str,
    'va': bool,    
})

class R2ChecksumsEntry(TypedDict, total=True):  # ij (checksums entry)
    md5: str
    sha1: str
    sha256: str    


class R2BinInfo(TypedDict, total=True):         # ij
    core: R2BinInfoCore
    bin: Optional[R2BinInfoBin]
    checksums: R2ChecksumsEntry
#endregion RADARE2 BINARY INFO
#endregion RADARE2
