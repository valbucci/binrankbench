"""Task definitions for each signature strategy, consumed by TaskRunner worker processes."""

import mmh3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Callable
from multiprocessing import Queue
from multiprocessing.pool import Pool

from binrankbench.common.hex import hexvalue_to_bytes
from binrankbench.common.types import (R2CodeInfoIn, R2ZignatureIn, R2CallGraph,
                                   R2FunctionInfoIn)    
from binrankbench.modules.ccbhash import CCBHashBuilder, CCBHashFeatures
from binrankbench.modules.machoke import fcode_to_machoke_line
from binrankbench.modules.fss import FunctionSimSearch, fcode_to_hash_ir, fcode_to_components
from binrankbench.modules.generate.result import (Result, CCBHashResult, MachokeResult,
                                      Catalog1Result,
                                      FunctionDetailsResult,
                                      FunctionSimSearchResult, BytesResult,
                                      ResultWrapper, SkipInfo)
from binrankbench.common.hex import HexStr, apply_bitmask
from binrankbench.modules.generate.logging import get_logger
from binrankbench.modules.catalog1 import Catalog1

logger = get_logger("tasks")


@dataclass
class Task:
    func_addr: int
    
    def run(self) -> Result:
        raise NotImplementedError("Subclasses must implement this method")
    
    @classmethod
    def handle_error(cls, result_type: type[Result], func_addr: int, 
                     error: Exception) -> Result:
        msg = (f"Error running {cls.__name__} for function at address "
               f"{hex(func_addr)}: {error}")
        if isinstance(error, (ValueError, ImportError)):
            # Expected: missing input data or optional dependency not installed
            logger.debug(msg)
        else:
            logger.warning(msg)
        return result_type(func_addr=func_addr, success=False, error=error)


import json

@dataclass
class JSONPayloadTask(Task):
    cfg_raw_str: Optional[str] = None
    zignature_raw_str: Optional[str] = None
    finfo_raw_str: Optional[str] = None
    preloaded_func_code: Optional[R2CodeInfoIn] = None
    preloaded_func_zignature: Optional[R2ZignatureIn] = None
    preloaded_func_info: Optional[R2FunctionInfoIn] = None
    
    @property
    def func_code(self) -> Optional[R2CodeInfoIn]:
        if self.preloaded_func_code is not None:
            return self.preloaded_func_code
        if not hasattr(self, "_cached_func_code"):
            parsed = json.loads(self.cfg_raw_str) if self.cfg_raw_str else None
            if parsed is not None and not parsed:
                raise ValueError("CFG data is empty")
            self._cached_func_code = parsed
        return self._cached_func_code

    @property
    def func_zignature(self) -> Optional[R2ZignatureIn]:
        if self.preloaded_func_zignature is not None:
            return self.preloaded_func_zignature
        if not hasattr(self, "_cached_func_zignature"):
            parsed = json.loads(self.zignature_raw_str) if self.zignature_raw_str else None
            if parsed is not None and not parsed:
                raise ValueError("Zignature data is empty")
            self._cached_func_zignature = parsed
        return self._cached_func_zignature

    @property
    def func_info(self) -> Optional[R2FunctionInfoIn]:
        if self.preloaded_func_info is not None:
            return self.preloaded_func_info
        if not hasattr(self, "_cached_func_info"):
            parsed = json.loads(self.finfo_raw_str) if self.finfo_raw_str else None
            if parsed is not None and not parsed:
                raise ValueError("Function info data is empty")
            self._cached_func_info = parsed
        return self._cached_func_info


@dataclass
class CCBHashTask(JSONPayloadTask):
    func_callgraph: Optional[R2CallGraph] = None  # Keep for backward compatibility
    binary_name: Optional[str] = None 
    callgraph_getter: Optional[Callable[[str], Optional[R2CallGraph]]] = None

    def get_missing_fields(self) -> list[str]:
        """Check which required fields are missing."""
        missing = []
        if self.finfo_raw_str is None and self.preloaded_func_info is None:
            missing.append("func_info")
        if self.zignature_raw_str is None and self.preloaded_func_zignature is None:
            missing.append("func_zignature")
        if self.cfg_raw_str is None and self.preloaded_func_code is None:
            missing.append("func_code")
            
        callgraph_ok = False
        if self.func_callgraph is not None:
            callgraph_ok = True
        elif self.callgraph_getter is not None and self.binary_name is not None:
            try:
                callgraph = self.callgraph_getter(self.binary_name)
                if callgraph is not None:
                    callgraph_ok = True
            except Exception:
                pass
        
        if not callgraph_ok:
            missing.append("callgraph")
            
        return missing

    def _run(self) -> CCBHashResult:
        missing = self.get_missing_fields()
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")
        
        # Get call graph: use provided one, or lookup via getter
        callgraph = self.func_callgraph
        if callgraph is None and self.callgraph_getter is not None and self.binary_name is not None:
            callgraph = self.callgraph_getter(self.binary_name)
        
        if callgraph is None:
            raise ValueError("Call graph is required but not available")
        
        (func_name, cfg_str, call_graph_str, instr_types, var_args, 
            var_locals, ninstructions, indegree, outdegree, nvars, cc, nblocks,
            stackframe ) = CCBHashBuilder.build_features(
                self.func_info, self.func_zignature, self.func_code, # type: ignore
                callgraph)                                 # type: ignore 
    
        features = CCBHashFeatures(
            func_name, cfg_str, call_graph_str, instr_types, var_args, 
            var_locals, ninstructions, indegree, outdegree, nvars, cc, 
            nblocks, stackframe
        )
        
        return CCBHashResult(func_addr=self.func_addr, success=True,
                             func_name=func_name,
                             error=None, ccbhash_features=features)

    def run(self) -> CCBHashResult:
        try:
            return self._run()
        except Exception as e:
            return self.handle_error(CCBHashResult, self.func_addr, e) # type: ignore



@dataclass
class MachokeTask(JSONPayloadTask):

    def _run(self) -> MachokeResult:
        if self.func_code is None:
            raise ValueError("func_code must be not None")
        
        if fcode_to_machoke_line is None:
            raise ImportError("binrankbench.modules.machoke module not available (mmh3 not installed)")
        if mmh3 is None:
            raise ImportError("mmh3 module not installed")
        
        machoke_line = fcode_to_machoke_line(self.func_code)
        machoke_digest = HexStr(mmh3.hash(machoke_line) & 0xFFFFFFFF)
        raw_name = self.func_info.get('name') if self.func_info else None
        return MachokeResult(func_addr=self.func_addr, success=True,
                             func_name=raw_name,
                             error=None, machoke_line=machoke_line,
                             machoke_digest=machoke_digest)

    def run(self) -> MachokeResult:
        try:
            return self._run()
        except Exception as e:
            return self.handle_error(MachokeResult, self.func_addr, e) # type: ignore



@dataclass
class Catalog1Task(JSONPayloadTask):
    func_bytes: Optional[bytes] = None
    bit_masked_func_bytes: Optional[bytes] = None
    
    def _run(self) -> Catalog1Result:
        target_bytes = None
        if self.func_bytes and len(self.func_bytes) > 0:
            target_bytes = self.func_bytes
        elif self.bit_masked_func_bytes and len(self.bit_masked_func_bytes) > 0:
            target_bytes = self.bit_masked_func_bytes
        elif self.func_zignature and self.func_zignature.get("bytes"):
            from binrankbench.common.hex import HexStr
            func_size = self.func_info.get("size", float("inf")) if self.func_info else float("inf")
            if func_size <= 500:
                target_bytes = bytes(HexStr(self.func_zignature["bytes"]))
            
        if not target_bytes:
            raise ValueError("No raw bytes could be extracted from input data")
        
        if len(target_bytes) < 4:
            raise ValueError(f"Data too small for Catalog1 (length {len(target_bytes)} < 4 bytes)")
            
        raw_name = self.func_info.get('name') if self.func_info else None
        return Catalog1Result(
            func_addr=self.func_addr, 
            success=True,
            func_name=raw_name,
            catalog1=Catalog1.compute_digest(target_bytes, 64),
        )
    
    def run(self) -> Catalog1Result:
        try:
            return self._run()
        except Exception as e:
            return self.handle_error(Catalog1Result, self.func_addr, e) # type: ignore


@dataclass
class BytesTask(JSONPayloadTask):
    func_bytes: Optional[bytes] = None
    bit_masked_func_bytes: Optional[bytes] = None
    
    def _run(self) -> BytesResult:
        nibble_mask = None
        try:
            from binrankbench.modules.byte_signature import ByteSignature
            if self.func_zignature is not None:
                cc = self.func_info.get("cc", 0) if self.func_info else 0
                sig = ByteSignature(
                    raw_bytes=self.func_zignature["bytes"],
                    mask=self.func_zignature["mask"],
                    cc=cc
                )
                # raw bytes are the same, just grab mask
                nibble_mask = sig.mask
        except Exception as e:
            logger.error(f"Error generating nibble byte signature for function {hex(self.func_addr)}: {e}")

        bit_mask = None
        try:
            from binrankbench.modules.byte_signature import ByteSignature
            if self.func_bytes is not None and self.bit_masked_func_bytes is not None:
                min_len = min(len(self.func_bytes), len(self.bit_masked_func_bytes))
                cc = self.func_info.get("cc", 0) if self.func_info else 0
                sig = ByteSignature(
                    raw_bytes=self.func_bytes[:min_len],
                    mask=self.bit_masked_func_bytes[:min_len],
                    cc=cc
                )
                bit_mask = sig.mask
        except Exception as e:
            logger.error(f"Error generating bit byte signature for function {hex(self.func_addr)}: {e}")

        raw_bytes_to_store = None
        if self.func_zignature is not None and self.func_zignature.get("bytes"):
            zig_bytes = hexvalue_to_bytes(self.func_zignature["bytes"])
            raw_bytes_to_store = zig_bytes[:500]

        if not raw_bytes_to_store:
            raise ValueError("No raw bytes could be extracted from zignature data")

        raw_name = self.func_info.get('name') if self.func_info else None
        return BytesResult.from_raw_bytes(
            func_addr=self.func_addr,
            success=True,
            func_name=raw_name,
            raw_bytes=raw_bytes_to_store,
            nibble_sig_mask=nibble_mask,
            bit_sig_mask=bit_mask
        )
    
    def run(self) -> BytesResult:
        try:
            return self._run()
        except Exception as e:
            return self.handle_error(BytesResult, self.func_addr, e) # type: ignore

@dataclass
class FunctionDetailsTask(JSONPayloadTask):
    
    def _run(self) -> FunctionDetailsResult:
        zignature = self.func_zignature
        info = self.func_info
        
        if zignature is None and info is None:
            raise ValueError("func_zignature and func_info must be not None")
        
        if zignature is None:
            logger.debug(f"func_zignature is None for function at address "
                         f"{hex(self.func_addr)}, using empty dictionary")
            zignature = {}
        if info is None:
            logger.debug(f"func_info is None for function at address "
                         f"{hex(self.func_addr)}, using empty dictionary")
            info = {}
        
        return FunctionDetailsResult(
            func_addr=self.func_addr, 
            success=True,
            func_name=info.get("name"),
            error=None,
            name=info.get("name"),
            size=info.get("size"),
            ninstructions=info.get("ninstrs"),
            stackframe=info.get("stackframe"),
            outdegree=info.get("outdegree"),
            indegree=info.get("indegree"),
            nargs=info.get("nargs"),
            nlocals=info.get("nlocals"),
            bbsum=zignature.get("graph", {}).get("bbsum"),
            ebbs=info.get("ebbs"),
            edges=info.get("edges"),
            nblocks=info.get("nbbs"),
            cc=info.get("cc"),
        )
        
    def run(self) -> FunctionDetailsResult:
        try:
            return self._run()
        except Exception as e:
            return self.handle_error(FunctionDetailsResult, self.func_addr, e) # type: ignore
        
        
@dataclass
class FunctionSimSearchTask(JSONPayloadTask):
    compute_original: bool = True
    compute_marcelli: bool = True
    compute_marcelli_weighted: bool = True
    
    def _run(self) -> FunctionSimSearchResult:
        if self.func_code is None:
            raise ValueError("func_code must be not None")
        
        if FunctionSimSearch is None or fcode_to_components is None:
            raise ImportError("binrankbench.modules.fss module not available (functionsimsearch not installed)")
            
        # Optimization: Parse CFG JSON once instead of 3 times
        nodes, edges, instructions = fcode_to_components(self.func_code)
        
        fss_plain = None
        if self.compute_original:
            fss_plain = FunctionSimSearch.from_components(
                nodes, edges, instructions,
                mode="original"
            )
        
        mss_plain = None
        if self.compute_marcelli:
            mss_plain = FunctionSimSearch.from_components(
                nodes, edges, instructions,
                mode="marcelli"
            )
            
        mss_weighted = None
        if self.compute_marcelli_weighted:
            mss_weighted = FunctionSimSearch.from_components(
                nodes, edges, instructions,
                mode="marcelli",
                marcelli_weights={"mnem_weight": .05, "graphlet_weight": 1., 
                                  "immediate_weight": 4.}
            )
        
        raw_name = self.func_info.get('name') if self.func_info else None
        return FunctionSimSearchResult(
            func_addr=self.func_addr, success=True,
            func_name=raw_name,
            error=None,
            fss_plain=str(fss_plain) if fss_plain else None,
            mss_plain=str(mss_plain) if mss_plain else None,
            mss_weighted=str(mss_weighted) if mss_weighted else None
        )
        
    def run(self) -> FunctionSimSearchResult:
        try:
            return self._run()
        except Exception as e:
            return self.handle_error(FunctionSimSearchResult, self.func_addr, e) # type: ignore


TASK_KEYS = {
    CCBHashTask: "ccbhash",
    MachokeTask: "machoke",
    Catalog1Task: "catalog1",
    BytesTask: "bytes",
    FunctionDetailsTask: "function_details",
    FunctionSimSearchTask: "fss",
}

TASK_CLASSES = {
    key: value for key, value in TASK_KEYS.items()
}

# Task priorities: lower number = higher priority (processed first)
# Based on average execution time: fastest tasks get highest priority
TASK_PRIORITIES = {
    "function_details": 1,  # ~0.00003s per task (29922.8/s)
    "bytes": 2,              # ~0.0004s per task (2419.8/s)
    "machoke": 3,           # ~0.0005s per task (2029.7/s)
    "fss": 4,               # ~0.012s per task (82.0/s)
    "catalog1": 5,          # ~0.043s per task (23.2/s)
    "ccbhash": 7,           # ~4.7s per task (slowest)
}


@dataclass
class TaskWrapper:
    func_addr: int
    task: Task
    output_path: Path
    binary_name: str
    func_name: Optional[str] = None
    size: int = 0
    result: Optional[Result] = None
    
    def execute_task(self) -> bool:
        """Execute task and store result. Returns True if successful."""
        try:
            self.result = self.task.run()
            return self.result.success
        except Exception as e:
            self.result = self.task.handle_error(Result, self.func_addr, e)
            return False
    
    def get_result_wrapper(self) -> 'ResultWrapper':
        """Build ResultWrapper with output path and result."""
        if self.result is None:
            raise RuntimeError("Cannot get result before executing task")
        return ResultWrapper(
            output_path=self.output_path,
            func_addr=self.func_addr,
            result=self.result,
            binary_name=self.binary_name,
            func_name=self.func_name
        )


def get_task_priority(task_wrapper: TaskWrapper) -> int:
    """Get priority for a task wrapper. Lower number = higher priority."""
    # Find the task type by checking which class the task is an instance of
    task_type = None
    for task_class, key in TASK_KEYS.items():
        if isinstance(task_wrapper.task, task_class):
            task_type = key
            break
    
    if task_type is None:
        # Unknown task type - give it lowest priority
        return 999
    return TASK_PRIORITIES.get(task_type, 999)


@dataclass
class TaskGroup(Task):
    binary_name: str
    output_dir: Path
    func_addr: int
    func_name: Optional[str] = None
    func_info: Optional[R2FunctionInfoIn] = None
    func_zignature: Optional[R2ZignatureIn] = None
    func_code: Optional[R2CodeInfoIn] = None
    func_callgraph: Optional[R2CallGraph] = None
    func_bytes: Optional[bytes] = None
    bit_masked_func_bytes: Optional[bytes] = None
    
    def get_output_path(self, output_dir: Path, task_key: str) -> Path:
        return output_dir / f"{self.binary_name}_{task_key}.csv"
    
    @property
    def machoke_output_path(self) -> Path:
        return self.get_output_path(self.output_dir, "machoke")
    
    @property
    def ccbhash_output_path(self) -> Path:
        return self.get_output_path(self.output_dir, "ccbhash")
        
    @property
    def catalog1_output_path(self) -> Path:
        return self.get_output_path(self.output_dir, "catalog1")
    
    @property
    def function_details_output_path(self) -> Path:
        return self.get_output_path(self.output_dir, "function_details")
    
    @property
    def function_sim_search_output_path(self) -> Path:
        return self.get_output_path(self.output_dir, "fss")
    
    @property
    def bytes_output_path(self) -> Path:
        return self.get_output_path(self.output_dir, "bytes")
    
    def get_nbbs(self) -> Optional[int]:
        """Get the number of basic blocks from available data sources."""
        if self.func_info is not None:
            return self.func_info.get("nbbs")
        if self.func_zignature is not None:
            graph = self.func_zignature.get("graph")
            if graph is not None:
                return graph.get("nbbs")
        return None
    
    @property
    def machoke_task(self) -> Task:
        return MachokeTask(
            func_addr=self.func_addr,
            preloaded_func_code=self.func_code
        )
    
    @property
    def ccbhash_task(self) -> Task:
        return CCBHashTask(
            func_addr=self.func_addr,
            preloaded_func_info=self.func_info,
            preloaded_func_zignature=self.func_zignature,
            preloaded_func_code=self.func_code,
            func_callgraph=None,  
            binary_name=self.binary_name,  
            callgraph_getter=None  
        )
        
    @property
    def catalog1_task(self) -> Task:
        return Catalog1Task(
            func_addr=self.func_addr,
            func_bytes=self.func_bytes,
            preloaded_func_zignature=self.func_zignature,
            bit_masked_func_bytes=self.bit_masked_func_bytes,
            preloaded_func_info=self.func_info
        )
    
    @property
    def function_details_task(self) -> Task:
        return FunctionDetailsTask(
            func_addr=self.func_addr,
            preloaded_func_info=self.func_info,
            preloaded_func_zignature=self.func_zignature
        )
    
    @property
    def function_sim_search_task(self) -> Task:
        return FunctionSimSearchTask(
            func_addr=self.func_addr,
            preloaded_func_code=self.func_code
        )
    
    @property
    def bytes_task(self) -> Task:
        return BytesTask(
            func_addr=self.func_addr,
            func_bytes=self.func_bytes,
            preloaded_func_zignature=self.func_zignature,
            bit_masked_func_bytes=self.bit_masked_func_bytes,
            preloaded_func_info=self.func_info
        )
    
    def run_machoke_task(self) -> Result:
        return self.machoke_task.run()
    
    def run_ccbhash_task(self) -> Result:
        return self.ccbhash_task.run()

    def run_catalog1_task(self) -> Result:
        return self.catalog1_task.run()
    
    def run_function_details_task(self) -> Result:
        return self.function_details_task.run()
    
    def run_function_sim_search_task(self) -> Result:
        return self.function_sim_search_task.run()
    
    def run_bytes_task(self) -> Result:
        return self.bytes_task.run()
        
    def get_tasks(self) -> list[Task]:
        return [self.machoke_task, self.ccbhash_task, self.catalog1_task,
                self.bytes_task, self.function_details_task, self.function_sim_search_task]
    
    def prepare_tasks(
        self,
        checkpoint_data: Optional[dict[str, set[int]]] = None
    ) -> tuple[list[TaskWrapper], list[SkipInfo], list[str]]:
        """
        Explode TaskGroup into individual TaskWrappers with output paths.
        Only creates tasks when the required data is available.
        
        Functions with < 5 basic blocks are filtered out entirely.
        
        Args:
            checkpoint_data: Optional dict mapping task_type -> set of completed
            func_addrs. If provided, skip tasks for functions already completed
            in previous run.
        
        Returns:
            tuple: (task_wrappers, skip_infos, checkpointed_task_types)
        """
        task_wrappers: list[TaskWrapper] = []
        skip_infos: list[SkipInfo] = []
        checkpointed_tasks: list[str] = []
        
        # Skip functions with < 5 basic blocks for ALL tasks
        nbbs = self.get_nbbs()
        if nbbs is not None and nbbs < 5:
            # Create skip entries for all potential task types
            skip_reason = f"function has only {nbbs} basic blocks (minimum 5 required)"
            for task_name in ["machoke", "ccbhash", "catalog1",
                            "bytes", "function_details", "fss"]:
                skip_infos.append(SkipInfo(
                    func_addr=self.func_addr,
                    task_type=task_name,
                    reason=skip_reason,
                    output_path=self.output_dir / f"{self.binary_name}_{task_name}.csv",
                    binary_name=self.binary_name
                ))
            return [], skip_infos, checkpointed_tasks
        
        # Machoke requires: func_code
        if self.func_code is not None:
            # Check if already processed in checkpoint
            if (
                checkpoint_data
                and self.func_addr in checkpoint_data.get("machoke", set())
            ):
                checkpointed_tasks.append("machoke")
            else:
                task_wrappers.append(TaskWrapper(
                    func_addr=self.func_addr,
                    task=self.machoke_task,
                    output_path=self.output_dir / f"{self.binary_name}_machoke.csv",
                    binary_name=self.binary_name
                ))
        else:
            skip_infos.append(SkipInfo(
                func_addr=self.func_addr,
                task_type="machoke",
                reason="missing CFG data",
                output_path=self.output_dir / f"{self.binary_name}_machoke.csv",
                binary_name=self.binary_name
            ))
        
        # CCBHash requires: func_info, func_zignature, func_code
        # Call graph will be looked up via manager (no longer included in TaskGroup)
        if all([self.func_info, self.func_zignature, self.func_code]):
            # Check if already processed in checkpoint
            if (
                checkpoint_data
                and self.func_addr in checkpoint_data.get("ccbhash", set())
            ):
                checkpointed_tasks.append("ccbhash")
            else:
                task_wrappers.append(TaskWrapper(
                    func_addr=self.func_addr,
                    task=self.ccbhash_task,
                    output_path=self.output_dir / f"{self.binary_name}_ccbhash.csv",
                    binary_name=self.binary_name
                ))
        else:
            missing = []
            if not self.func_info: missing.append("finfo")
            if not self.func_zignature: missing.append("zignature")
            if not self.func_code: missing.append("cfg")

            skip_infos.append(SkipInfo(
                func_addr=self.func_addr,
                task_type="ccbhash",
                reason=f"missing {', '.join(missing)}",
                output_path=self.output_dir / f"{self.binary_name}_ccbhash.csv",
                binary_name=self.binary_name
            ))
        
        has_bytes = False
        if self.func_bytes is not None and len(self.func_bytes) > 0:
            has_bytes = True
        elif self.func_zignature is not None and self.func_zignature.get("bytes"):
            func_size = self.func_info.get("size", float("inf")) if self.func_info else float("inf")
            zignature_bytes_hex = self.func_zignature.get("bytes")
            if zignature_bytes_hex is not None and len(zignature_bytes_hex) > 2: # At least one byte
                if func_size <= 500:
                    self.func_bytes = bytes.fromhex(zignature_bytes_hex)
                    has_bytes = True

        # Catalog1 requires: func_bytes (min 4 bytes) OR func_zignature
        if has_bytes:
            if len(self.func_bytes) >= 4: # type: ignore
                # Check if already processed in checkpoint
                if (
                    checkpoint_data
                    and self.func_addr in checkpoint_data.get("catalog1", set())
                ):
                    checkpointed_tasks.append("catalog1")
                else:
                    task_wrappers.append(TaskWrapper(
                        func_addr=self.func_addr,
                        task=self.catalog1_task,
                        output_path=self.output_dir / f"{self.binary_name}_catalog1.csv",
                        binary_name=self.binary_name
                    ))
            else:
                skip_infos.append(SkipInfo(
                    func_addr=self.func_addr,
                    task_type="catalog1",
                    reason=f"Data too small for Catalog1 (length {len(self.func_bytes)} < 4 bytes)", # type: ignore
                    output_path=self.output_dir / f"{self.binary_name}_catalog1.csv",
                    binary_name=self.binary_name
                ))
        else:
            skip_infos.append(SkipInfo(
                func_addr=self.func_addr,
                task_type="catalog1",
                reason="missing bytes or function too large",
                output_path=self.output_dir / f"{self.binary_name}_catalog1.csv",
                binary_name=self.binary_name
            ))
        
        # Bytes requires: func_bytes OR func_zignature (for nibble mask)
        if has_bytes:
            # Check if already processed in checkpoint
            if (
                checkpoint_data
                and self.func_addr in checkpoint_data.get("bytes", set())
            ):
                checkpointed_tasks.append("bytes")
            else:
                task_wrappers.append(TaskWrapper(
                    func_addr=self.func_addr,
                    task=self.bytes_task,
                    output_path=self.output_dir / f"{self.binary_name}_bytes.csv",
                    binary_name=self.binary_name
                ))
        else:
            skip_infos.append(SkipInfo(
                func_addr=self.func_addr,
                task_type="bytes",
                reason="missing bytes and function too large to use zignature",
                output_path=self.output_dir / f"{self.binary_name}_bytes.csv",
                binary_name=self.binary_name
            ))
        
        # FunctionDetails requires: func_info OR func_zignature
        if self.func_info is not None or self.func_zignature is not None:
            # Check if already processed in checkpoint
            if (
                checkpoint_data
                and self.func_addr in checkpoint_data.get("function_details", set())
            ):
                checkpointed_tasks.append("function_details")
            else:
                task_wrappers.append(TaskWrapper(
                    func_addr=self.func_addr,
                    task=self.function_details_task,
                    output_path=self.output_dir / f"{self.binary_name}_function_details.csv",
                    binary_name=self.binary_name
                ))
        else:
            skip_infos.append(SkipInfo(
                func_addr=self.func_addr,
                task_type="function_details",
                reason="missing finfo and zignature",
                output_path=self.output_dir / f"{self.binary_name}_function_details.csv",
                binary_name=self.binary_name
            ))
        
        # FunctionSimSearch requires: func_code
        if self.func_code is not None:
            # Check if already processed in checkpoint
            if (
                checkpoint_data
                and self.func_addr in checkpoint_data.get("fss", set())
            ):
                checkpointed_tasks.append("fss")
            else:
                task_wrappers.append(TaskWrapper(
                    func_addr=self.func_addr,
                    task=self.function_sim_search_task,
                    output_path=self.output_dir / f"{self.binary_name}_fss.csv",
                    binary_name=self.binary_name
                ))
        else:
            skip_infos.append(SkipInfo(
                func_addr=self.func_addr,
                task_type="fss",
                reason="missing CFG data",
                output_path=self.output_dir / f"{self.binary_name}_fss.csv",
                binary_name=self.binary_name
            ))
        
        return task_wrappers, skip_infos, checkpointed_tasks
