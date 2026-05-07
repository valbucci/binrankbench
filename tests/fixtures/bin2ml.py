import pytest
import json
from pathlib import Path
from typing import Iterator

from binrankbench.common.bin2ml import Bin2MLPipe
from binrankbench.common.context import BIN2ML_PATH
from binrankbench.common.types import (R2CallGraph, R2CodeInfoIn, BIN2ML_CFG,
                                   R2FunctionInfoIn, R2ZignatureIn)

BIN2ML_DATA_TYPES = ["cfg", "cg", "finfo", "fvars"]

@pytest.fixture(scope="session")
def bin2ml() -> Bin2MLPipe:
    try:
        return Bin2MLPipe(BIN2ML_PATH)
    except FileNotFoundError:
        pytest.skip(f"Bin2ML binary not found at {BIN2ML_PATH}.")

@pytest.fixture(scope="session")
def extracted_dir(data_dir) -> Path:
    return data_dir / "bin2ml"

@pytest.fixture(params=BIN2ML_DATA_TYPES, scope="session")
def bin2ml_data_path(extracted_dir, binary_name, request) -> Path:
    ext = ".json"
    if request.param in ("bytes", "bytes-masked", "func-cfg"):
        ext = ""
    return extracted_dir / f"{binary_name}_{request.param}{ext}"

@pytest.fixture(scope="session")
def bin2ml_data(bin2ml_data_path) -> dict:
    if not bin2ml_data_path.exists():
        pytest.skip(f"Data path not found: {bin2ml_data_path}")

    file_ext = bin2ml_data_path.suffix
    if bin2ml_data_path.is_file():
        if file_ext == ".json":
            with open(bin2ml_data_path, "r") as f:
                return json.load(f)
        else:
            raise ValueError(f"Unsupported file extension: {file_ext}")

    data_type = bin2ml_data_path.as_posix().split("_")[-1]
    if data_type in ("bytes", "bytes-masked"):
        glob_str = "*.raw.bin" if data_type == "bytes" else "*.mask.bin"
        return {
            file_path: file_path.read_bytes()
            for file_path in bin2ml_data_path.glob(glob_str)
        }
    elif data_type == "func-cfg":
        return {
            file_path: json.load(open(file_path))
            for file_path in bin2ml_data_path.glob("*.json")
        }
    else:
        raise ValueError(f"Unsupported data type: {data_type}")


@pytest.fixture(scope="session")
def global_call_graph(extracted_dir, binary_name) -> R2CallGraph:
    file_path = extracted_dir / f"{binary_name}_cg.json"
    if not file_path.exists():
        pytest.skip(f"Global call graph file not found: {file_path}")
    with open(file_path, "r") as f:
        return json.load(f)

@pytest.fixture(scope="session")
def cfg_list(extracted_dir, binary_name) -> BIN2ML_CFG:
    file_path = extracted_dir / f"{binary_name}_cfg.json"
    if not file_path.exists():
        pytest.skip(f"CFG file not found: {file_path}")
    with open(file_path, "r") as f:
        return json.load(f)

@pytest.fixture(scope="session")
def cfg(cfg_list: BIN2ML_CFG) -> R2CodeInfoIn:
    return cfg_list[0][0]

@pytest.fixture(scope="session")
def func_cfg_iterator(extracted_dir, binary_name) -> Iterator[R2CodeInfoIn]:
    file_path = extracted_dir / f"{binary_name}_func-cfg.jsonl"
    if not file_path.exists():
        pytest.skip(f"Function CFG file not found: {file_path}")

    def _iterator():
        with open(file_path, "r") as f:
            for line in f:
                yield json.loads(line)

    return _iterator()

@pytest.fixture(scope="session")
def finfo_list(extracted_dir, binary_name) -> list[R2FunctionInfoIn]:
    file_path = extracted_dir / f"{binary_name}_finfo.json"
    if not file_path.exists():
        pytest.skip(f"Function info file not found: {file_path}")
    with open(file_path, "r") as f:
        return json.load(f)

@pytest.fixture(scope="session")
def finfo(finfo_list: list[R2FunctionInfoIn]) -> R2FunctionInfoIn:
    return finfo_list[0]

@pytest.fixture(scope="session")
def zigs_list(extracted_dir, binary_name) -> list[R2ZignatureIn]:
    file_path = extracted_dir / f"{binary_name}_zigs.json"
    if not file_path.exists():
        pytest.skip(f"Zigs file not found: {file_path}")
    with open(file_path, "r") as f:
        return json.load(f)

@pytest.fixture(scope="session")
def zignature(zigs_list: list[R2ZignatureIn]) -> R2ZignatureIn:
    return zigs_list[0]
