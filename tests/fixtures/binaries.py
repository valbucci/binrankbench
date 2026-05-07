import pytest
from pathlib import Path

BINARY_NAME = "git_2-47-1.exe"

@pytest.fixture(scope="session")
def binary_name() -> str:
    return BINARY_NAME

@pytest.fixture(scope="session")
def binaries_dir(data_dir) -> Path:
    return data_dir / "binaries"

@pytest.fixture(scope="session")
def binary_path(binaries_dir, binary_name) -> Path:
    return binaries_dir / binary_name

@pytest.fixture(scope="session")
def temp_dir(tmp_path_factory) -> Path:
    """Create a temporary directory for test files."""
    return tmp_path_factory.mktemp("temp_dir")
