"""Result dataclasses for computed signatures and skip records produced by pipeline workers."""

import zlib
from pathlib import Path
from base64 import b64encode, b64decode
from dataclasses import dataclass
from typing import Any, Optional
from multiprocessing import Queue
from binrankbench.modules.ccbhash import CCBHashFeatures


@dataclass
class SkipInfo:
    """Information about a skipped task."""
    func_addr: int
    task_type: str  # e.g., "ccbhash", "machoke", "fss"
    reason: str     # e.g., "missing zignature data"
    binary_name: str
    output_path: Path = Path(".")   # DEPRECATED: it's not used anymore.
                                    # TODO: remove once binrankbench.generate module is refactored
    
    def to_csv_row(self) -> list[Any]:
        """Convert skip info to CSV row."""
        return [f"{self.func_addr:x}", self.reason]
    
    @staticmethod
    def csv_headers() -> list[str]:
        """Return CSV headers for skip info."""
        return ["func_addr", "skip_reason"]


@dataclass
class Result:
    func_addr: int
    success: bool
    func_name: Optional[str] = None
    error: Optional[Exception] = None
    
    @classmethod
    def csv_headers(cls) -> list[str]:
        """Return CSV column names. Override in subclasses."""
        return ["func_addr", "success", "error"]
    
    def to_csv_row(self) -> list[Any]:
        """Convert result to CSV row values. Override in subclasses."""
        return [f"{self.func_addr:x}", self.success, 
                str(self.error) if self.error else ""]


@dataclass
class CCBHashResult(Result):
    ccbhash_features: Optional[CCBHashFeatures] = None
    cfg_feature_override: Optional[str] = None
    
    @property
    def ccbhash_digest(self) -> Optional[str]:
        if self.ccbhash_features is None:
            return None
        return self.ccbhash_features.ccbhash
        
    @property
    def cfg_override_ccbhash_digest(self) -> Optional[str]:
        if self.cfg_feature_override is None:
            return None
        
        if self.ccbhash_features is None:
            return None
        
        plain_features = self.ccbhash_features.to_dict(complete=False)
        plain_features["cfg"] = self.cfg_feature_override
        return CCBHashFeatures.from_dict(plain_features).ccbhash
    
    @classmethod
    def csv_headers(cls) -> list[str]:
        return ["func_addr", "name", "ccbhash", "cfg", "call_graph", 
                "opcodes", "var_args", "var_locals", "ninstructions",
                "indegree", "outdegree", "nvars", "cc", "nblocks", "stackframe"]
    
    def to_csv_row(self) -> list[Any]:
        if not self.success or self.ccbhash_features is None:
            return [f"{self.func_addr:x}"] + [""] * 14
        
        f = self.ccbhash_features
        return [
            f"{self.func_addr:x}",
            f.name or "",
            str(f.ccbhash) if f.ccbhash else "",
            f.cfg or "",
            f.call_graph or "",
            f.opcodes or "",
            f.var_args or "",
            f.var_locals or "",
            str(f.ninstructions) if f.ninstructions is not None else "",
            str(f.indegree) if f.indegree is not None else "",
            str(f.outdegree) if f.outdegree is not None else "",
            str(f.nvars) if f.nvars is not None else "",
            str(f.cc) if f.cc is not None else "",
            str(f.nblocks) if f.nblocks is not None else "",
            str(f.stackframe) if f.stackframe is not None else ""
        ]

@dataclass
class MachokeResult(Result):
    machoke_line: Optional[str] = None
    machoke_digest: Optional[str] = None
    
    @classmethod
    def csv_headers(cls) -> list[str]:
        return ["func_addr", "machoke_digest", "machoke_line"]
    
    def to_csv_row(self) -> list[Any]:
        return [
            f"{self.func_addr:x}",
            self.machoke_digest or "",
            self.machoke_line or ""
        ]



@dataclass
class Catalog1Result(Result):
    catalog1: Optional[str] = None
    
    @classmethod
    def csv_headers(cls) -> list[str]:
        return ["func_addr", "catalog1"]
    
    def to_csv_row(self) -> list[Any]:
        return [
            f"{self.func_addr:x}",
            self.catalog1 or ""
        ]

@dataclass
class BytesResult(Result):
    """Stores the result of the bytes extraction. Bytes are base64 encoded."""
    raw_bytes: Optional[bytes] = None
    nibble_sig_mask: Optional[bytes] = None
    bit_sig_mask: Optional[bytes] = None

    def __post_init__(self, *args, **kwargs):
        # Cut-off to 500 bytes
        if self.raw_bytes:
            self.raw_bytes = self.raw_bytes[:500]
        if self.nibble_sig_mask:
            self.nibble_sig_mask = self.nibble_sig_mask[:500]
        if self.bit_sig_mask:
            self.bit_sig_mask = self.bit_sig_mask[:500]
    
    @staticmethod
    def _encode_bytes(bytes_: bytes, compression_level: int = 1) -> str:
        comp = zlib.compress(bytes_, level=compression_level)
        return b64encode(comp).decode("utf-8")
    
    @staticmethod
    def _decode_bytes(encoded_bytes: str) -> bytes:
        comp = b64decode(encoded_bytes.encode("utf-8"))
        return zlib.decompress(comp)
    
    @classmethod
    def from_raw_bytes(cls, func_addr: int, success: bool,
                       func_name: Optional[str] = None,
                       raw_bytes: Optional[bytes] = None,
                       nibble_sig_mask: Optional[bytes] = None,
                       bit_sig_mask: Optional[bytes] = None,
                       error: Optional[Exception] = None):
        """Create BytesResult from raw bytes (only raw_bytes is encoded)."""
        return cls(
            func_addr=func_addr,
            success=success,
            func_name=func_name,
            error=error,
            raw_bytes=(raw_bytes if raw_bytes else None),
            nibble_sig_mask=(nibble_sig_mask if nibble_sig_mask else None),
            bit_sig_mask=(bit_sig_mask if bit_sig_mask else None)
        )
    
    @classmethod
    def csv_headers(cls) -> list[str]:
        return ["func_addr", "raw_bytes", "nibble_sig_mask", "bit_sig_mask"]
    
    def to_csv_row(self) -> list[Any]:
        return [
            f"{self.func_addr:x}",
            "" if self.raw_bytes is None else self._encode_bytes(self.raw_bytes),
            "" if self.nibble_sig_mask is None else self._encode_bytes(self.nibble_sig_mask),
            "" if self.bit_sig_mask is None else self._encode_bytes(self.bit_sig_mask)
        ]


@dataclass
class FunctionDetailsResult(Result):
    bbhash: Optional[str] = None
    name: Optional[str] = None
    size: Optional[int] = None
    ninstructions: Optional[int] = None
    stackframe: Optional[int] = None
    outdegree: Optional[int] = None
    indegree: Optional[int] = None
    nargs: Optional[int] = None
    nlocals: Optional[int] = None
    bbsum: Optional[int] = None
    ebbs: Optional[int] = None
    edges: Optional[int] = None
    nblocks: Optional[int] = None
    cc: Optional[int] = None
    
    @classmethod
    def csv_headers(cls) -> list[str]:
        return ["func_addr", "bbhash", "name", "size", "ninstructions",
                "stackframe", "outdegree", "indegree", "nargs", "nlocals",
                "bbsum", "ebbs", "edges", "nblocks", "cc"]
    
    def to_csv_row(self) -> list[Any]:
        return [
            f"{self.func_addr:x}",
            self.bbhash or "",
            self.name or "",
            self.size or "",
            self.ninstructions or "",
            self.stackframe or "",
            self.outdegree or "",
            self.indegree or "",
            self.nargs or "",
            self.nlocals or "",
            self.bbsum or "",
            self.ebbs or "",
            self.edges or "",
            self.nblocks or "",
            self.cc or ""
        ]

@dataclass
class FunctionSimSearchResult(Result):
    fss_plain: Optional[str] = None
    # fss_graphonly: Optional[str] = None
    # fss_ir: Optional[str] = None
    # fss_no_mnem: Optional[str] = None
    mss_plain: Optional[str] = None
    mss_weighted: Optional[str] = None
    # mss_graphonly: Optional[str] = None
    # mss_ir: Optional[str] = None
    # mss_no_mnem: Optional[str] = None
    
    @classmethod
    def csv_headers(cls) -> list[str]:
        return [
            "func_addr", 
            "fss_plain", 
            # "fss_graphonly", "fss_ir", "fss_no_mnem", 
            "mss_plain", 
            "mss_weighted"
            # "mss_graphonly", "mss_ir", "mss_no_mnem"
        ]
    
    def to_csv_row(self) -> list[Any]:
        return [
            f"{self.func_addr:x}",
            self.fss_plain or "",
            # self.fss_graphonly or "",
            # self.fss_ir or "",
            # self.fss_no_mnem or "",
            self.mss_plain or "",
            self.mss_weighted or ""
            # self.mss_graphonly or "",
            # self.mss_ir or "",
            # self.mss_no_mnem or ""
        ]


@dataclass
class ResultGroup:
    func_addr: int
    func_name: Optional[str]
    ccbhash_result: CCBHashResult
    machoke_result: MachokeResult
    catalog1_result: Catalog1Result
    bytes_result: BytesResult
    function_details_result: FunctionDetailsResult
    function_sim_search_result: FunctionSimSearchResult

RESULT_KEYS = {
    CCBHashResult: "ccbhash",
    MachokeResult: "machoke",
    Catalog1Result: "catalog1",
    BytesResult: "bytes",
    FunctionDetailsResult: "function_details",
    FunctionSimSearchResult: "fss"
}

RESULT_CLASSES = {
    key: value for key, value in RESULT_KEYS.items()
}


@dataclass
class ResultWrapper:
    output_path: Path
    func_addr: int
    result: Result
    binary_name: str
    func_name: Optional[str] = None
