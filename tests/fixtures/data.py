import pytest
import json
from pathlib import Path

TESTS_ROOT = Path(__file__).parent.parent

@pytest.fixture(scope="session")
def data_dir() -> Path:
    """Get the path to the test data directory."""
    return TESTS_ROOT / "test_data"

@pytest.fixture(scope="session")
def r2_agfj_data(data_dir):
    """Load r2 agfj function graph data."""
    data_file = data_dir / "r2_agfj.json"
    if data_file.exists():
        return json.loads(data_file.read_text())
    pytest.skip("r2_agfj.json test data not found")
