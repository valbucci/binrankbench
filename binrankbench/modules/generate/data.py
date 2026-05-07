"""Binary data loading: discovers, validates, and streams per-function analysis data from disk."""

import json
import csv
import sys
import tarfile
import logging
import re
from enum import Enum, auto
from typing import TypedDict, Optional, Self, Iterator, Any, TextIO, Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from abc import ABC, abstractmethod

from binrankbench.common.bin2ml import ExtractMode
from binrankbench.common.types import (R2CodeInfoIn, R2ZignatureIn, R2CallGraph,
                                   R2FunctionInfoIn, BIN2ML_CFG)
from binrankbench.modules.generate import get_logger
from binrankbench.modules.ccbhash import CCBHashBuilder
from binrankbench.modules.catalog1 import Catalog1
from binrankbench.common.hex import HexStr
from binrankbench.common.utils import get_address


logger = get_logger("data")

# Increase CSV field size limit to avoid checkpoint read failures on large fields
csv.field_size_limit(sys.maxsize)


class DataType(Enum):
    CFG                 = auto()
    BYTES               = auto()
    BYTES_MASKED_NIBBLE = auto()
    BYTES_MASKED_BIT    = auto()
    ZIGNATURES          = auto()
    FUNCTION_INFO       = auto()
    CALL_GRAPH          = auto()
    BINARY_INFO         = auto()

    @classmethod
    def get_modes_from_data_type(cls, data_type: "DataType"
                                 ) -> tuple[ExtractMode, ...]:
        """
        Returns the list of possible suffixes needed for a given DataType enum 
        value. As long as one is present, the necessary data will be loaded.
        """
        if data_type == cls.CFG:
            return ("cfg", "func-cfg")
        elif data_type == cls.BYTES:
            return ("bytes", "bytes-masked")
        elif data_type == cls.BYTES_MASKED_NIBBLE:
            return ("zigs",)
        elif data_type == cls.BYTES_MASKED_BIT:
            return ("bytes-masked",)
        elif data_type == cls.ZIGNATURES:
            return ("zigs",)
        elif data_type == cls.FUNCTION_INFO:
            return ("finfo",)
        elif data_type == cls.CALL_GRAPH:
            return ("cg",)
        elif data_type == cls.BINARY_INFO:
            return ("bininfo",)
        raise ValueError(f"Unknown DataType: {data_type}")
    
    @classmethod
    def get_data_type_from_mode(cls, mode: ExtractMode) -> "DataType":
        """Returns the DataType enum value for a given type suffix."""
        for data_type in cls:
            if mode in cls.get_modes_from_data_type(data_type):
                return data_type
        raise ValueError(f"Unknown mode: {mode}")
    
    @property
    def modes(self) -> tuple[ExtractMode, ...]:
        return self.get_modes_from_data_type(self)


@dataclass
class BytesDataPaths:
    data_path: Path
    index_path: Path

    @property
    def ok(self) -> bool:
        return self.data_path.is_file()


@dataclass
class FetchedDataPath:
    data_path: Optional[Path]
    index_path: Optional[Path] = field(default=None)


@dataclass
class BinaryDataPaths:
    """Paths to the data files for a given binary."""
    cfg: Optional[Path]          = field(default=None)
    func_cfg: Optional[Path]     = field(default=None)
    zigs: Optional[Path]         = field(default=None)
    finfo: Optional[Path]        = field(default=None)
    cg: Optional[Path]           = field(default=None)
    bytes: Optional[BytesDataPaths]        = field(default=None)
    bytes_masked: Optional[BytesDataPaths] = field(default=None)
    binary_name: str = field(default="")
    
    def __post_init__(self):
        ctx = f"({self.binary_name}) " if self.binary_name else ""
        if self.cfg is not None and not self.cfg.is_file():
            logger.debug(f"{ctx}cfg file not found: {self.cfg}")
            self.cfg = None
        if self.func_cfg is not None and not self.func_cfg.exists():
            logger.debug(f"{ctx}func-cfg path not found: {self.func_cfg}")
            self.func_cfg = None
        if self.cfg is None and self.func_cfg is None:
            logger.warning(f"{ctx}No cfg files found")
        
        if self.bytes is not None and not self.bytes.ok:
            logger.debug(f"{ctx}bytes file not found: {self.bytes.data_path}")
            self.bytes = None
        if self.bytes_masked is not None and not self.bytes_masked.ok:
            logger.debug(f"{ctx}bytes-masked file not found: {self.bytes_masked.data_path}")
            self.bytes_masked = None
        if self.bytes is None and self.bytes_masked is None:
            logger.warning(f"{ctx}No bytes files found")

        if self.zigs is not None and not self.zigs.is_file():
            logger.warning(f"{ctx}zigs file not found: {self.zigs}")
            self.zigs = None
        if self.finfo is not None and not self.finfo.is_file():
            logger.warning(f"{ctx}finfo file not found: {self.finfo}")
            self.finfo = None
        if self.cg is not None and not self.cg.is_file():
            logger.warning(f"{ctx}cg file not found: {self.cg}")
            self.cg = None
            
    def __contains__(self, mode: ExtractMode) -> bool:
        if mode == "func-cfg":
            return self.func_cfg is not None
        elif mode == "bytes-masked":
            return self.bytes_masked is not None
        else:
            return getattr(self, mode) is not None
    
    def __getitem__(self, mode: ExtractMode) -> tuple[Optional[Path],
                                                      Optional[Path]]:
        """Returns the data path and index path (if any) for a given mode."""
        if mode == "func-cfg":
            return self.func_cfg, None
        
        elif mode == "bytes-masked":
            if self.bytes_masked is None:
                return None, None
            else:
                return (self.bytes_masked.data_path,
                        self.bytes_masked.index_path)
        
        elif mode == "bytes":
            if self.bytes is None:
                return None, None
            else:
                return (self.bytes.data_path, self.bytes.index_path)
        
        else:
            return getattr(self, mode), None
        
    def fetch_data_paths(self, data_types: list[DataType]
                         ) -> dict[DataType, FetchedDataPath]:
        data_paths_index = {}
        for data_type in data_types:
            data_path, index_path = None, None
            match data_type:
                case DataType.BYTES:
                    if self.bytes is not None and self.bytes.ok:
                        data_path, index_path = (self.bytes.data_path,
                                                 self.bytes.index_path)
                    break

                case DataType.BYTES_MASKED_BIT:
                    if self.bytes_masked is not None and self.bytes_masked.ok:
                        data_path, index_path = (self.bytes_masked.data_path,
                                                 self.bytes_masked.index_path)
                    break

                case DataType.CFG:
                    if self.cfg is not None and self.cfg.is_file():
                        data_path = self.cfg
                    elif self.func_cfg is not None and self.func_cfg.is_file():
                        data_path = self.func_cfg
                    break

                case _:
                    mode = data_type.modes[0]
                    data_path, index_path = self[mode]

            data_result = FetchedDataPath(data_path=data_path, 
                                          index_path=index_path)
            data_paths_index[data_type] = data_result
            
        return data_paths_index

    
REQUIRED_DATA_TYPES = {
    "ccbhash": (DataType.FUNCTION_INFO, DataType.ZIGNATURES, DataType.CFG, 
                DataType.CALL_GRAPH),
    "ccbhash_cfe": (DataType.FUNCTION_INFO, DataType.ZIGNATURES, DataType.CFG, 
                    DataType.CALL_GRAPH),
    "cfehash": (DataType.CFG,),
    "fss": (DataType.CFG,),
    "machoke": (DataType.CFG,),
    "catalog1": (DataType.BYTES,),
    "nibble_masked_catalog1": (DataType.ZIGNATURES,),
}


class BaseDataStreamer(ABC):
    
    def __init__(self, file_path: Path, 
                 propagate_exceptions: bool = True) -> None:
        self.file_path = file_path
        self._file_handle = None
        self._logger = logger.getChild(f"{self._classname}({self.file_name})")
        self._had_error = False
        self._propagate_exceptions = propagate_exceptions

    def __repr__(self) -> str:
        return f"{self._classname}(\"{self.file_path.absolute().as_posix()}\")"

    @property
    def _classname(self) -> str:
        return self.__class__.__name__
    
    @property
    def file_name(self) -> str:
        return self.file_path.name

    @property
    def ok(self) -> bool:
        return not self._had_error and self._file_handle is not None
    
    @property
    def file_handle(self) -> Any:
        if self._file_handle is None:
            raise RuntimeError("Accessed uninitialized file handle")
        return self._file_handle
    
    def _teardown(self) -> None:
        self._logger.debug("Closing file handle")
        if self._file_handle is not None:
            try:
                self.file_handle.close()
            except OSError as e:
                self._logger.exception(f"Failed to close file handle: {e}")
            finally:
                self._file_handle = None
    
    def __enter__(self) -> Self:
        try:
            self._file_handle = open(self.file_path, "r")
        except Exception as e:
            self._had_error = True
            self._teardown()
            self._logger.exception("Failed to open file")
            if self._propagate_exceptions:
                raise e
        return self
    
    def __exit__(self, exception_type, exception_value, 
                 exception_traceback) -> bool:
        self._teardown()
        if exception_type is not None:
            self._had_error = True
            if self._propagate_exceptions:
                self._logger.error("Exiting due to exception")
                return False
            else:
                self._logger.exception("Exiting due to exception")
                return True # Suppress exception
        return True
    
    @abstractmethod
    def _stream(self, *args: Any, **kwargs: Any) -> Iterator[Any]: ...
    
    def stream(self, *args: Any, **kwargs: Any) -> Iterator[Any]:
        try:
            with self:
                if not self.ok:
                    self._logger.error(
                        "Stream aborted: file handle not available.")
                    yield from ()
                    return

                yield from self._stream(*args, **kwargs)

        except Exception as e:
            self._had_error = True
            self._logger.exception("Unexpected error while streaming")
            if self._propagate_exceptions:
                raise e
            else:
                self._logger.debug("Swallowed exception; closing stream.")
            return
    

class JsonlDataStreamer(BaseDataStreamer):
    
    def __init__(self, file_path: Path, encoding: str = "utf-8",
                 errors: str = "strict", propagate_exceptions: bool = True
                 ) -> None:
        super().__init__(file_path, propagate_exceptions)
        self.encoding = encoding
        self.errors = errors
    
    def __enter__(self) -> Self:
        try:
            self._file_handle = open(self.file_path, "r", 
                                     encoding=self.encoding,
                                     errors=self.errors,
                                     newline="")
        except Exception as e:
            self._had_error = True
            self._teardown()
            self._logger.exception("Failed to open file")
            if self._propagate_exceptions:
                raise e
        return self

    def _stream(self, start_line: int = 1, lazy: bool = False) -> Iterator[tuple[dict, str]]:
        current_line = 0
        while True:
            try:
                line = self.file_handle.readline()
            except UnicodeDecodeError as e:
                self._had_error = True
                self._logger.exception("Bad UTF-8 while reading line "
                                       f"{current_line}. Skipping.")
                current_line += 1
                if self.errors == "strict":
                    self._logger.error("Propagating UnicodeDecodeError as "
                                       "cannot recover with strict error mode")
                    raise e
                continue
            
            if not line: # EOF reached
                self._logger.info("Reached end of file; closing stream.")
                return

            current_line += 1
            if current_line < start_line:
                continue
            
            try:
                line_str = line.strip()
                if lazy:
                    # Parse JSON line faster with regexes
                    # 1. Skip if not a function or symbol line
                    if not re.search(r'"type"\s*:\s*"(fcn|sym)"', line_str):
                        continue

                    # 2. Strip out all arrays (blocks, xrefs, etc.) to leave only root-level scalar metadata
                    # Greedy .* ensures we swallow all nested block data.
                    metadata_str = re.sub(r'\[.*\]', '', line_str)

                    # 3. Now, the ONLY offset left is the root-level one
                    addr_match = re.search(r'"(?:offset|addr)"\s*:\s*(\d+)', metadata_str)
                    if not addr_match:
                        continue
                        
                    target_offset = int(addr_match.group(1))
                    size_match = re.search(r'"size"\s*:\s*(\d+)', metadata_str)
                    target_size = int(size_match.group(1)) if size_match else 0

                    mini_dict = {
                        "offset": target_offset,
                        "size": target_size
                    }
                    yield mini_dict, line_str
                else:
                    parsed = json.loads(line_str)
                    if "offset" not in parsed and "addr" not in parsed:
                        continue  # Must have an address identifier
                    if parsed.get("type") not in ("fcn", "sym", None):
                        continue  # Skip non-function data
                    yield parsed, line_str
            except Exception as e:
                self._had_error = True
                self._logger.exception(
                    f"Unexpected error on line {current_line} ({e}). Skipping.")




class TarDataStreamer(BaseDataStreamer):
    def __init__(self, archive_path: Path, index_path: Path,
                 propagate_exceptions: bool = True) -> None:
        super().__init__(archive_path, propagate_exceptions)
        self.index_path = index_path
        self._file_metadata_index: dict[str, tuple[int, str]] = {}
        self._is_setup = False
        
    @property
    def is_index_ok(self) -> bool:
        return self._is_setup and not self._had_error
        
    @property
    def metadata_index(self) -> dict[str, tuple[int, str]]:
        if not self._is_setup:
            raise RuntimeError("Cannot access metadata index before setup")

        return self._file_metadata_index

    def setup_index(self) -> Self:
        if self._is_setup:
            self._logger.debug("Index already setup, skipping setup")
            return self

        content_lines = []
        if self.index_path.is_file():
            if not self.index_path.as_posix().endswith(".csv"):
                self._logger.warning(f"Index file {self.index_path} doesn't seem "
                                     "to be a CSV file; proceeding anyway.")
            with open(self.index_path, "r", encoding="utf-8", newline="") as f:
                content_lines = f.readlines()
        else:
            # Fallback 1: look for a file with the same name alongside the tar
            index_name = self.index_path.name
            sibling_path = self.file_path.parent / index_name
            if sibling_path.is_file() and sibling_path != self.index_path:
                self._logger.info(
                    f"Index file not found at {self.index_path}; "
                    f"using sibling file {sibling_path}"
                )
                with open(sibling_path, "r", encoding="utf-8", newline="") as f:
                    content_lines = f.readlines()
            else:
                # Fallback 2: search inside the tar itself
                self._logger.info(f"Index file {self.index_path} not found on disk, extracting from {self.file_path}")
                with tarfile.open(self.file_path, "r:*") as temp_tar:
                    index_member = None
                    for member in temp_tar.getmembers():
                        if member.name.endswith(index_name):
                            index_member = member
                            break
                    if index_member is None:
                        raise FileNotFoundError(f"Index file {self.index_path} does not exist on disk, "
                                                f"and no file ending in {index_name} was found in {self.file_path}.")
                    with temp_tar.extractfile(index_member) as f: # type: ignore
                        content_lines = f.read().decode("utf-8").splitlines()

        reader = csv.DictReader(content_lines)
        for row in reader:
            try:
                func_path = Path(row["output_path"])
                func_file_name = func_path.name
                func_address = int(row["address"])
                func_name = row["name"]
            except KeyError:
                self._logger.exception(f"Missing key in index file")
                self._logger.debug(f"Row: {row}")
                continue
            except Exception as e:
                self._logger.exception(f"Error processing row ({e})")
                self._logger.debug(f"Row: {row}")
                continue
            else:
                self._file_metadata_index[func_file_name] = (
                    func_address,
                    func_name
                )
        
        self._is_setup = True
        self._logger.info("Index setup complete (%d entries)", 
                          len(self._file_metadata_index))

        return self
    
    def __enter__(self) -> Self:
        try:
            self.setup_index()
            self._file_handle = tarfile.open(self.file_path, "r:*")
        
        except FileNotFoundError as e:
            self._had_error = True
            error_msg = f"Archive file not found: {self.file_path}"
            if self._propagate_exceptions:
                self._logger.error(error_msg)
                raise RuntimeError(error_msg) from e
            else:
                self._logger.exception(error_msg)
        
        except tarfile.ReadError as e:
            self._had_error = True
            error_msg = f"Could not read tar file: {self.file_path}"
            if self._propagate_exceptions:
                raise RuntimeError(error_msg) from e
            else:
                self._logger.exception(error_msg)

        except Exception as e:
            self._had_error = True
            error_msg = f"Unexpected error while opening file: {self.file_path}"
            if self._propagate_exceptions:
                self._logger.error(error_msg)
                raise RuntimeError(error_msg) from e
            else:
                self._logger.exception(error_msg)
        
        # Validate setup was successful before allowing streaming
        if not self._is_setup:
            self._had_error = True
            error_msg = "Index setup failed or was not completed"
            if self._propagate_exceptions:
                raise RuntimeError(error_msg)
            else:
                self._logger.exception(error_msg)
        
        return self
    
    def _stream(self) -> Iterator[tuple[int, str, str, bytes]]:
        """
        Yields (address, name, member_name, content_bytes) for each file listed in the index CSV.
        Reads members directly from the tar in memory (no extraction to disk).
        """
        # Track expected files from CSV index vs streamed from archive
        needed = set(self.metadata_index.keys())
        streamed: set[str] = set()

        stream_count = 0
        while True:
            member = self.file_handle.next()
            if member is None:
                self._logger.info("No more members in archive; closing stream.")
                break
            
            if not member.isfile():
                self._logger.debug(f"Skipping non-file member: {member.name}")
                continue
            
            stream_count += 1
            member_path = PurePosixPath(member.name)
            member_name = member_path.name
            if member_name not in needed:
                self._logger.debug(f"Skipping non-needed file {member_path}")
                continue
            
            if member_name in streamed:
                self._logger.warning(
                    f"Duplicate member {member_name} found in archive. "
                    f"Skipping subsequent occurrence {member_path} ..."
                )
                continue
            
            try:
                func_address, func_name = self.metadata_index[member_name]
                with self.file_handle.extractfile(member) as fobj:
                    if fobj is None:
                        raise IOError("extractfile returned None")
                    content = fobj.read()

                yield func_address, func_name, member_name, content
                    
            except KeyError:
                # This should never happen, as we checked for existence above
                self._logger.error(f"File {member_name} not found in index")
                continue

            except Exception as e:
                self._had_error = True
                self._logger.exception("Unexpected error extracting file "
                                        f"{member_path} ({e}). Skipping.")
                continue

            
            streamed.add(member_name)
            if len(streamed) == len(needed):
                # No need to keep iterating, we have everything from the index
                self._logger.info("All expected files found in archive")
                return
            
        # Report any missing entries
        missing = needed - streamed
        if len(missing) > 0:
            if stream_count > 0:
                self._had_error = True
                self._logger.warning(f"Missing {len(missing)} files from index.")
                for m in missing:
                    self._logger.debug(f"File \"{m}\" in index but not streamed")
            else:
                self._logger.warning(f"The archive is empty.")




@dataclass(slots=True)
class FunctionsDataEntry:
    """
    Used to group raw data for a given function. 
    Note that the R2CallGraph is not included as it is a binary-level dict."""
    address: int
    cfg: Optional[R2CodeInfoIn] = field(default=None)
    zignature: Optional[R2ZignatureIn] = field(default=None)
    finfo: Optional[R2FunctionInfoIn] = field(default=None)
    fbytes_raw: Optional[bytes] = field(default=None)
    fbytes_bitmask: Optional[bytes] = field(default=None)
    cfg_raw_str: Optional[str] = field(default=None)
    zignature_raw_str: Optional[str] = field(default=None)
    finfo_raw_str: Optional[str] = field(default=None)
    _name: Optional[str] = field(default=None)
    
    @property
    def name(self) -> Optional[str]:
        if self._name is None:
            self._name = self._setup_name()
        return self._name
    
    
    @staticmethod
    def get_canonical_name(name: str) -> str:
        name = name.removeprefix("method.")
        name = name.removeprefix("sym.")
        return name
    
    @name.setter
    def name(self, name: str) -> None:
        self._name = self.get_canonical_name(name)
    
    def _setup_address(self) -> int:
        addresses_set = set()
        if self.address is not None:
            addresses_set.add(self.address)
        if self.cfg is not None:
            addresses_set.add(get_address(self.cfg))
        if self.zignature is not None:
            addresses_set.add(get_address(self.zignature))
        if self.finfo is not None:
            addresses_set.add(get_address(self.finfo))
        if len(addresses_set) == 0:
            raise ValueError("No addresses found for the function")
        if len(addresses_set) > 1:
            raise ValueError("Multiple addresses found for the same function")
        return addresses_set.pop()
    
    def _setup_name(self) -> Optional[str]:
        name = None
        if self.finfo is not None:
            if self.finfo.get("name") is not None:
                name = self.get_canonical_name(self.finfo["name"])

        return name
    
    def __post_init__(self):
        self.address = self._setup_address()
        self._name = self._setup_name()
    
    @property
    def fbytes_nibblemask(self) -> Optional[bytes]:
        if self.zignature is None:
            return None
        return bytes(HexStr(self.zignature["mask"]))
    
    @classmethod
    def merge_data(cls, data1: "FunctionsDataEntry", data2: "FunctionsDataEntry"
                   ) -> "FunctionsDataEntry":
        if data1.address != data2.address:
            raise ValueError("Addresses do not match: "
                             f"{data1.address} != {data2.address}")
        if (data1.name is not None and data2.name is not None 
            and data1.name != data2.name
            ):
            logger.warning("Function data names do not match: "
                           f"{data1.name} != {data2.name}")
            
        # Note: Could lead to data loss if non-null entries are different
        return cls(
            address=data1.address,
            cfg=data1.cfg or data2.cfg,
            zignature=data1.zignature or data2.zignature,
            finfo=data1.finfo or data2.finfo,
            fbytes_raw=data1.fbytes_raw or data2.fbytes_raw,
            fbytes_bitmask=data1.fbytes_bitmask or data2.fbytes_bitmask,
            cfg_raw_str=data1.cfg_raw_str or data2.cfg_raw_str,
            zignature_raw_str=data1.zignature_raw_str or data2.zignature_raw_str,
            finfo_raw_str=data1.finfo_raw_str or data2.finfo_raw_str
        )


class BinaryFunctionsDataManager:
    def __init__(self, binary_path: Path, data_paths: BinaryDataPaths,
                 callgraph_path: Path) -> None:
        self.binary_path = binary_path
        self.data_paths = data_paths
        self.callgraph_path = callgraph_path
        self.data_entries: dict[int, FunctionsDataEntry] = {}
        self.callgraph: R2CallGraph = {} # type: ignore
        self._is_setup = False
        self._logger = logger.getChild(f"{self.__class__.__name__}("
                                       f"{self.binary_name})")

    @property
    def binary_name(self) -> str:
        return self.binary_path.name

    def setup_cfg(self) -> Self:
        if self.data_paths.cfg is None:
            raise RuntimeError("CFG data path is not set")
        
        cfg_path = self.data_paths.cfg
        with open(cfg_path, "r") as f:
            cfg_list: BIN2ML_CFG = json.load(f)
            for (cfg,) in cfg_list:
                faddr = get_address(cfg)
                try:
                    data_entry = self.data_entries.get(faddr)
                    if data_entry is None:
                        data_entry = FunctionsDataEntry(address=faddr)
                    data_entry.cfg = cfg
                    data_entry.cfg_raw_str = json.dumps(cfg)
                    self.data_entries[faddr] = data_entry
                except Exception as e:
                    self._logger.exception(
                        "Error processing CFG data for function "
                        f"at address {faddr:x} ({e})")
        return self
    
    def setup_func_cfg(self, lazy: bool = False) -> Self:
        if self.data_paths.func_cfg is None:
            raise RuntimeError("func-CFG data path is not set")
        
        func_cfg_path = self.data_paths.func_cfg
        
        files_to_stream = []
        if func_cfg_path.is_dir():
            files_to_stream = list(func_cfg_path.glob("*.jsonl"))
            if not files_to_stream:
                self._logger.debug(f"func-cfg directory is empty or has no .jsonl files: {func_cfg_path}")
                return self
        else:
            files_to_stream = [func_cfg_path]
            
        for path in files_to_stream:
            jsonl_streamer = JsonlDataStreamer(path)
            for func_cfg, func_cfg_str in jsonl_streamer.stream(lazy=lazy):
                faddr = get_address(func_cfg)
                try:
                    data_entry = self.data_entries.get(faddr)
                    if data_entry is None:
                        data_entry = FunctionsDataEntry(address=faddr)
                    data_entry.cfg = func_cfg
                    data_entry.cfg_raw_str = func_cfg_str
                    self.data_entries[faddr] = data_entry
                except Exception as e:
                    self._logger.exception(
                        "Error processing func-CFG data for function "
                        f"at address {faddr:x} in {path.name} ({e})")
        return self

    def setup_zigs(self) -> Self:
        if self.data_paths.zigs is None:
            raise RuntimeError("Zigs data path is not set")
        
        zigs_path = self.data_paths.zigs
        with open(zigs_path, "r") as f:
            zigs: list[R2ZignatureIn] = json.load(f)
            for zignature in zigs:
                faddr = get_address(zignature)
                try:
                    data_entry = self.data_entries.get(faddr)
                    if data_entry is None:
                        data_entry = FunctionsDataEntry(address=faddr)
                    data_entry.zignature = zignature
                    # Removed redundant json.dumps here, moved to lazy serialization in poster
                    self.data_entries[faddr] = data_entry
                except Exception as e:
                    self._logger.exception(
                        "Error processing Zigs data for function "
                        f"at address {faddr:x} ({e})")
        return self
    
    def setup_finfo(self) -> Self:
        if self.data_paths.finfo is None:
            raise RuntimeError("Finfo data path is not set")
        
        finfo_path = self.data_paths.finfo
        with open(finfo_path, "r") as f:
            finfo_list: list[R2FunctionInfoIn] = json.load(f)
            for finfo in finfo_list:
                faddr = get_address(finfo)
                try:
                    data_entry = self.data_entries.get(faddr)
                    if data_entry is None:
                        data_entry = FunctionsDataEntry(address=faddr)
                    data_entry.finfo = finfo
                    # Removed redundant json.dumps here, moved to lazy serialization in poster
                    self.data_entries[faddr] = data_entry
                except Exception as e:
                    self._logger.exception(
                        "Error processing Finfo data for function "
                        f"at address {faddr:x} ({e})")
        return self

    def setup_bytes(self) -> Self:
        if self.data_paths.bytes is None or not self.data_paths.bytes.ok:
            # Don't raise - will try fallback from bytes-masked later
            self._logger.debug("Bytes data path is not set or is not valid; "
                             "will try fallback from bytes-masked if available")
            return self

        # Prefer bytes-masked.tar if available since it contains both raw and mask
        if self.data_paths.bytes_masked is not None and self.data_paths.bytes_masked.ok:
            self._logger.info("Bytes-masked data available; skipping bytes.tar extraction")
            return self
        
        try:
            bytes_path = self.data_paths.bytes.data_path
            bytes_index_path = self.data_paths.bytes.index_path
            tar_streamer = TarDataStreamer(bytes_path, bytes_index_path)
            for func_address, func_name, member_name, content in tar_streamer.stream():
                try:
                    data_entry = self.data_entries.get(func_address)
                    if data_entry is None:
                        data_entry = FunctionsDataEntry(address=func_address)
                        data_entry.name = func_name
                    # Only set if not already set (will be overwritten by bytes-masked if it exists)
                    if data_entry.fbytes_raw is None:
                        data_entry.fbytes_raw = content
                    self.data_entries[func_address] = data_entry
                except Exception as e:
                    self._logger.exception(
                        "Error processing Bytes data for function "
                        f"at address {func_address:x} ({e})")
                    continue
        except Exception as e:
            # Log but don't raise - will try fallback from bytes-masked
            self._logger.warning(
                f"Failed to load bytes.tar ({e}); "
                "will try fallback from bytes-masked if available"
            )
        return self
    
    def setup_bytes_masked(self) -> Self:
        if (self.data_paths.bytes_masked is None 
            or not self.data_paths.bytes_masked.ok
            ):
            self._logger.debug("Bytes-masked data path is not set or tar is missing; skipping")
            return self

        bytes_masked_path = self.data_paths.bytes_masked.data_path
        bytes_masked_index_path = self.data_paths.bytes_masked.index_path

        # Pass 1: stream .mask.bin files using the masked index (e.g. 00-func-index_bytes-masked.csv)
        try:
            tar_streamer = TarDataStreamer(bytes_masked_path, bytes_masked_index_path)
            for func_address, func_name, member_name, content in tar_streamer.stream():
                try:
                    data_entry = self.data_entries.get(func_address)
                    if data_entry is None:
                        data_entry = FunctionsDataEntry(address=func_address)
                        data_entry.name = func_name
                    data_entry.fbytes_bitmask = content
                    self.data_entries[func_address] = data_entry
                except Exception as e:
                    self._logger.exception(
                        "Error processing Bytes-masked (mask) data for function "
                        f"at address {func_address:x} ({e})")
                    continue
        except Exception as e:
            self._logger.warning(
                f"Failed to load bytes-masked tar ({e}); "
                "skipping bytes-masked data for this binary"
            )
            return self

        # Pass 2: stream .raw.bin files using the raw index embedded in the same tar
        # The raw index has the same name but with 'bytes-masked' replaced by 'bytes'
        raw_index_path = bytes_masked_index_path.with_name(
            bytes_masked_index_path.name.replace("bytes-masked", "bytes")
        )
        try:
            tar_streamer_raw = TarDataStreamer(bytes_masked_path, raw_index_path)
            for func_address, func_name, member_name, content in tar_streamer_raw.stream():
                try:
                    data_entry = self.data_entries.get(func_address)
                    if data_entry is None:
                        data_entry = FunctionsDataEntry(address=func_address)
                        data_entry.name = func_name
                    data_entry.fbytes_raw = content
                    self.data_entries[func_address] = data_entry
                except Exception as e:
                    self._logger.exception(
                        "Error processing Bytes-masked (raw) data for function "
                        f"at address {func_address:x} ({e})")
                    continue
        except Exception as e:
            self._logger.warning(
                f"Could not load raw bytes index from bytes-masked.tar ({e}); "
                "raw bytes may be missing."
            )

        return self
    
    def setup_callgraph(self) -> Self:
        if not self.callgraph_path.is_file():
            raise FileNotFoundError(f"Callgraph data file could not be "
                                    f"found: {self.callgraph_path}")
        with open(self.callgraph_path, "r") as f:
            self.callgraph = json.load(f)
        return self
    
    def setup_data_type(self, data_type: DataType) -> Self:
        match data_type:
            case DataType.CFG:
                if self.data_paths.cfg is not None:
                    return self.setup_cfg()
                else:
                    return self.setup_func_cfg()
            case DataType.ZIGNATURES:
                return self.setup_zigs()
            case DataType.FUNCTION_INFO:
                return self.setup_finfo()
            case DataType.BYTES:
                return self.setup_bytes()
            case DataType.BYTES_MASKED_BIT:
                return self.setup_bytes_masked()
            case DataType.CALL_GRAPH:
                return self.setup_callgraph()
            case _:
                raise NotImplementedError(f"Setup for data type {data_type} "
                                          "is not implemented yet")
    
    def setup(self, lazy: bool = False) -> Self:
        if self.data_paths.cfg is not None:
            self.setup_cfg()
        elif self.data_paths.func_cfg is not None:
            self.setup_func_cfg(lazy=lazy)
        
        if self.data_paths.zigs is not None:
            self.setup_zigs()
        if self.data_paths.finfo is not None:
            self.setup_finfo()
        if self.data_paths.bytes_masked is not None:
            self.setup_bytes_masked()
        elif self.data_paths.bytes is not None:
            # Only load raw bytes if bytes-masked data is not available
            self.setup_bytes()
        # Only load callgraph if file actually exists (optional data)
        if self.callgraph_path is not None and self.callgraph_path.is_file():
            self.setup_callgraph()
        self._is_setup = True
        return self
    
    def iterate_functions_data(self,
                               sort_by_address: bool = True,
                               include_callgraph: bool = False  # NEW: Default False
                               ) -> Iterator[tuple[int, 
                                                    Optional[str], 
                                                    Optional[R2CodeInfoIn],
                                                    Optional[R2ZignatureIn],
                                                    Optional[R2FunctionInfoIn],
                                                    Optional[str],
                                                    Optional[str],
                                                    Optional[str],
                                                    Optional[R2CallGraph],
                                                    Optional[bytes],
                                                    Optional[bytes]
                                                ]]:
        if sort_by_address:
            logger.info("Sorting data entries by address")
            data_entries = sorted(self.data_entries.items(), key=lambda x: x[0])
        else:
            data_entries = self.data_entries.items()

        for address, func_data in data_entries:
            yield (
                address,
                func_data.name,
                func_data.cfg,
                func_data.zignature,
                func_data.finfo,
                func_data.cfg_raw_str,
                func_data.zignature_raw_str,
                func_data.finfo_raw_str,
                self.callgraph if include_callgraph else None,  # Only include if requested
                func_data.fbytes_raw,
                func_data.fbytes_bitmask
            )
    
    def get_callgraph(self) -> Optional[R2CallGraph]:
        """Get the global call graph for this binary."""
        if self.callgraph_path is None:
            return None
        if not self._is_setup:
            return None
        return self.callgraph if self.callgraph else None


import pickle
import gzip
import timeit
from tqdm import tqdm
from tqdm.contrib.logging import logging_redirect_tqdm


def get_data_manager(binary_path: Path, raw_data_dir: Path):
    binary_name = binary_path.name
    data_paths = BinaryDataPaths(
        cfg=raw_data_dir / f"{binary_name}_cfg.json",
        func_cfg=raw_data_dir / f"{binary_name}_func-cfg.jsonl",
        zigs=raw_data_dir / f"{binary_name}_zigs.json",
        finfo=raw_data_dir / f"{binary_name}_finfo.json",
        bytes=BytesDataPaths(
            data_path=raw_data_dir / f"{binary_name}_bytes.tar",
            index_path=raw_data_dir / f"{binary_name}_bytes_func-index.csv"),
        bytes_masked=BytesDataPaths(
            data_path=raw_data_dir / f"{binary_name}_bytes-masked.tar",
            index_path=raw_data_dir / f"{binary_name}_bytes-masked_func-index.csv"),
        cg=raw_data_dir / f"{binary_name}_cg.json")
    callgraph_path = raw_data_dir / f"{binary_name}_cg.json"

    data_manager = BinaryFunctionsDataManager(binary_path=binary_path,
                                              data_paths=data_paths,
                                              callgraph_path=callgraph_path)
    return data_manager

# if __name__ == "__main__":
#     # dataset_path = Path("/home/valbux/Desktop/marcelli_test/Dataset-1")
#     # binaries_path = dataset_path / "binaries"
#     # raw_data_path = dataset_path / "marcelli_test_raw_data"
#     # binary_path = binaries_path / "z3/arm32-clang-5.0-O0_z3"
#     # start_time = timeit.default_timer()
#     # data_paths = BinaryDataPaths(
#     #     cfg=raw_data_path / "z3/arm32-clang-5.0-O0_z3_cfg.json",
#     #     func_cfg=raw_data_path / "z3/arm32-clang-5.0-O0_z3_func-cfg.jsonl",
#     #     zigs=raw_data_path / "z3/arm32-clang-5.0-O0_z3_zigs.json",
#     #     finfo=raw_data_path / "z3/arm32-clang-5.0-O0_z3_finfo.json",
#     #     bytes=BytesDataPaths(data_path=raw_data_path / "z3/arm32-clang-5.0-O0_z3_bytes.tar",
#     #                          index_path=raw_data_path / "z3/arm32-clang-5.0-O0_z3_bytes_func-index.csv"),
#     #     bytes_masked=BytesDataPaths(data_path=raw_data_path / "z3/arm32-clang-5.0-O0_z3_bytes-masked.tar",
#     #                                 index_path=raw_data_path / "z3/arm32-clang-5.0-O0_z3_bytes-masked_func-index.csv"),
#     #     cg=raw_data_path / "z3/arm32-clang-5.0-O0_z3_cg.json")
    
#     # data_manager = BinaryFunctionsDataManager(binary_path=binary_path,
#     #                                           data_paths=data_paths,
#     #                                           callgraph_path=raw_data_path / "z3/arm32-clang-5.0-O0_z3_cg.json")
#     data_manager = get_data_manager(binary_path=Path("/home/valbux/Desktop/marcelli_test/Dataset-1/binaries/z3/arm32-clang-5.0-O0_z3"),
#                                     raw_data_dir=Path("/home/valbux/Desktop/marcelli_test/Dataset-1/marcelli_test_raw_data/z3"))
#     data_manager.setup()

#     output_file = Path("z3_arm32-clang-5.0-O0_z3_ccbhash.csv")
#     CSV_HEADERS = [
#         "address", "name", "ccbhash"
#     ]
#     file_handle = open(output_file, "w", newline="")
#     writer = csv.writer(file_handle)
#     # writer.writerow(CSV_HEADERS)

#     n_functions = len(data_manager.data_entries)
#     batch_size = 100
#     with (logging_redirect_tqdm(loggers=[logger]),
#           open(output_file, "w", newline="") as file_handle):
#         writer = csv.writer(file_handle)
#         writer.writerow(CSV_HEADERS)
#         rows_batch = []
#         for func_data in tqdm(data_manager.iterate_functions_data(), 
#                               total=n_functions, position=1, desc="Functions"):
#             (address, name, cfg, zignature, finfo, fbytes_raw, fbytes_bitmask, 
#             callgraph) = func_data
#             logger.info(f"Processing function @ {address:x}: {name}")
#             writer.writerow((f"{address:x}", name))
#             if finfo is not None:
#                 size = finfo["size"]
#                 ninstructions = finfo["ninstrs"]
#                 stackframe = finfo["stackframe"]
#                 outdegree = finfo["outdegree"]
#                 indegree = finfo["indegree"]
#                 nargs = finfo.get("nargs", 0)
#                 nlocals = finfo.get("nlocals", 0)
#             else:
#                 size = None
#                 ninstructions = None
#                 stackframe = None
#                 outdegree = None
#                 indegree = None
#                 nargs = None
#                 nlocals = None
            
#             if fbytes_raw is not None:
#                 catalog1_raw_long = Catalog1.from_input_data(fbytes_raw, 64)
#                 catalog1_raw_short = Catalog1.from_input_data(fbytes_raw, 16)
#             else:
#                 catalog1_raw_long = None
#                 catalog1_raw_short = None

#             if fbytes_bitmask is not None:
#                 catalog1_bitmasked_long = Catalog1.from_input_data(fbytes_bitmask, 64)
#                 catalog1_bitmasked_short = Catalog1.from_input_data(fbytes_bitmask, 16)
#             else:
#                 catalog1_bitmasked_long = None
#                 catalog1_bitmasked_short = None
            
#             if zignature is not None:
#                 bbsum = zignature["graph"]["bbsum"]
#                 ebbs = zignature["graph"]["ebbs"]
#                 edges = zignature["graph"]["edges"]
#                 nblocks = zignature["graph"]["nbbs"]
#                 cc = zignature["graph"]["cc"]
                
#                 bbhash = zignature["hash"]["bbhash"]
#                 zignature_bytes = HexStr(zignature["bytes"])
#                 zignature_mask = HexStr(zignature["mask"])
#                 zignature_masked_bytes = zignature_bytes & zignature_mask
#                 catalog1_masked_long = Catalog1.from_input_data(zignature_masked_bytes, 64)
#                 catalog1_masked_short = Catalog1.from_input_data(zignature_masked_bytes, 16)
#             else:
#                 bbsum = None
#                 ebbs = None
#                 edges = None
#                 nblocks = None
#                 cc = None
                
#                 bbhash = None
#                 zignature_bytes = None
#                 zignature_masked_bytes = None
                
#             if cfg is not None:
#                 fss_plain = FunctionSimSearch.from_fcode(cfg, mode="original")
#                 fss_graphonly = FunctionSimSearch.from_fcode(cfg, mode="original", 
#                                                             use_immediates=False, 
#                                                             use_mnemonics=False)
#                 fss_ir = FunctionSimSearch(
#                     *fcode_to_hash_ir(cfg, mode="original")
#                 )
#                 fss_no_mnem = FunctionSimSearch.from_fcode(cfg, mode="original", 
#                                                         use_mnemonics=False)
                
#                 mss_plain = FunctionSimSearch.from_fcode(cfg, mode="marcelli")
#                 mss_graphonly = FunctionSimSearch.from_fcode(cfg, mode="marcelli", 
#                                                             use_immediates=False, 
#                                                             use_mnemonics=False)
#                 mss_ir = FunctionSimSearch(
#                     *fcode_to_hash_ir(cfg, mode="marcelli")
#                 )
#                 mss_no_mnem = FunctionSimSearch.from_fcode(cfg, mode="marcelli", 
#                                                         use_mnemonics=False)
#                 machoke_digest = fcode_to_machoke_hash(cfg)
                
#             else:
#                 fss_plain = None
#                 fss_graphonly = None
#                 fss_ir = None
#                 fss_no_mnem = None
#                 mss_plain = None
#                 mss_graphonly = None
#                 mss_ir = None
#                 mss_no_mnem = None
#                 machoke_digest = None

#             if not (finfo is None or zignature is None or cfg is None 
#                     or callgraph is None):
#                 ccbhash = CCBHashBuilder.build(finfo, zignature, cfg, 
#                                             callgraph).ccbhash
#             else:
#                 logger.warning(f"Failed to generate CCBHash for function {name} at address {address}")
#                 ccbhash = None
                
#             row = {
#                 "address": address,
#                 "name": name or "",
#                 "size": size or "",
#                 "ninstructions": ninstructions or "",
#                 "stackframe": stackframe or "",
#                 "outdegree": outdegree or "",
#                 "indegree": indegree or "",
#                 "nargs": nargs or "",
#                 "nlocals": nlocals or "",
#                 "bbsum": bbsum or "",
#                 "ebbs": ebbs or "",
#                 "edges": edges or "",
#                 "nblocks": nblocks or "",
#                 "cc": cc or "",
                
#                 "bbhash": str(bbhash or ""),
#                 "zignature_masked_bytes": str(zignature_masked_bytes or ""),
#                 "catalog1_raw_long": str(catalog1_raw_long or ""),
#                 "catalog1_raw_short": str(catalog1_raw_short or ""),
#                 "catalog1_bitmasked_long": str(catalog1_bitmasked_long or ""),
#                 "catalog1_bitmasked_short": str(catalog1_bitmasked_short or ""),
#                 "ccbhash": str(ccbhash or ""),
#                 "fss_plain": str(fss_plain or ""),
#                 "fss_graphonly": str(fss_graphonly or ""),
#                 "fss_ir": str(fss_ir or ""),
#                 "fss_no_mnem": str(fss_no_mnem or ""),
#                 "mss_plain": str(mss_plain or ""),
#                 "mss_graphonly": str(mss_graphonly or ""),
#                 "mss_ir": str(mss_ir or ""),
#                 "mss_no_mnem": str(mss_no_mnem or ""),
#                 "machoke_digest": str(machoke_digest or ""),
#             }

#             rows_batch.append((address, name or "", ccbhash or ""))
#             if len(rows_batch) >= batch_size:
#                 writer.writerows(rows_batch)
#                 rows_batch = []
#                 file_handle.flush()
                
#         if rows_batch:
#             writer.writerows(rows_batch)
#             file_handle.flush()
#     print(f"Data written to {output_file}")


def get_processed_functions(binary_name: str, output_dir: Path, 
                           task_type: str) -> set[int]:
    """
    Read CSV file and return set of function addresses already processed.
    
    Used for incremental processing when resuming from a .log.part checkpoint.
    
    Args:
        binary_name: Name of binary (e.g., "mips32-clang-7-Os_z3")
        output_dir: Output directory containing CSV files
        task_type: Task type (e.g., "ccbhash", "machoke", "catalog1")
    
    Returns:
        Set of function addresses (as integers). Empty set if file doesn't exist
        or cannot be read.
    """
    csv_path = output_dir / f"{binary_name}_{task_type}.csv"
    
    processed = set()
    
    files_to_read = []
    if csv_path.exists():
        files_to_read.append(csv_path)
        
    if not files_to_read:
        return set()
    
    for path in files_to_read:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # func_addr is in hex format (e.g., "400abc")
                    func_addr_str = row.get('func_addr', '').strip()
                    if func_addr_str:
                        try:
                            func_addr = int(func_addr_str, 16)
                            processed.add(func_addr)
                        except ValueError:
                            # Skip malformed addresses
                            logger.debug("Skipping malformed func_addr in "
                                         f"{path}: {func_addr_str}")
                            continue
        except Exception as e:
            # If file is corrupted or unreadable, treat as empty
            # (will reprocess all functions for this task type)
            logger.warning(f"Could not read checkpoint from {path}: {e}")
            
    return processed