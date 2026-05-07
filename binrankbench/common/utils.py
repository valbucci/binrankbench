"""File iteration helpers and address parsing utilities shared across BinRankBench."""

import json
from pathlib import Path
from typing import Iterator, Optional

from binrankbench.common.hex import HexValue, HexStr
from binrankbench.common.types import BIN2ML_CFG, _HasOffsetOrAddr
from binrankbench.common.logging import LOGGER as base_logger


logger = base_logger.getChild("utils")


def iter_files(target_dir: Path, glob_str: str="*", recursive=False
               ) -> Iterator[Path]:
    glob_str = f"**/{glob_str}" if recursive else glob_str
    return target_dir.glob(glob_str)

def load_bin2ml_cfg_data(cfg_data_path: Path) -> BIN2ML_CFG:
    with open(cfg_data_path, "r") as f:
        return json.load(f)

def load_file_paths(search_root: str | Path, glob_str: str="*",
                    recursive=False) -> Iterator[Path]:
    glob_str = f"**/{glob_str}" if recursive else glob_str
    return Path(search_root).glob(glob_str)


#region ADDRESS HANDLING
ADDR_SENTINEL = 0xFFFFFFFFFFFFFFFF


def is_address_placeholder(address: Optional[int]) -> bool:
    return address is None or address == ADDR_SENTINEL


def get_address(data: _HasOffsetOrAddr) -> int:
    address = None
    if "offset" in data.keys():
        address = data["offset"] # type: ignore
    elif "addr" in data.keys():
        address = data["addr"] # type: ignore
    else:
        raise ValueError(f"Data does not have an offset or address: {data}")
    
    if is_address_placeholder(address):
        # This shoould never happen, we log it to be safe
        # but we don't want to raise an exception here
        logger.error(f"Address is placeholder: {address}")
        logger.debug(f"Data: {data}")
    return address
    
def set_address(data: _HasOffsetOrAddr, address: int) -> None:
    if "offset" in data:
        data["offset"] = address
    elif "addr" in data:
        data["addr"] = address
    else:
        raise ValueError(f"Data does not have an offset or address: {data}")

def is_address_set(data: _HasOffsetOrAddr) -> bool:
    try:
        addr = get_address(data)
        return not is_address_placeholder(addr)
    except ValueError:
        # No address/offset key found, so address is definitely not set
        return False
#endregion ADDRESS HANDLING
