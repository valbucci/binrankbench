pytest_plugins = [
    "tests.fixtures.data",
    "tests.fixtures.binaries",
    "tests.fixtures.bin2ml",
]

# Mark all tests in this suite as unit tests by default
import pytest
pytestmark = pytest.mark.unit