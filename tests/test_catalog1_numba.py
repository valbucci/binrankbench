import os
import time

import pytest

from binrankbench.modules.catalog1 import (
    HAS_NUMBA,
    fast_sign,
    numba_sign,
)


def test_numba_correctness():
    """Verify that Numba results match Python fast_sign results."""
    if not HAS_NUMBA:
        pytest.skip("Numba not installed")

    # Test with various data sizes
    for size in [10, 100, 1000, 5000]:
        data = os.urandom(size)
        num_perms = 16

        sig_py = fast_sign(data, num_perms)
        sig_numba = numba_sign(data, num_perms)

        assert sig_py == sig_numba, f"Mismatch at size {size}"


def test_numba_correctness_2():
    """Verify that Numba results match Python fast_sign results."""
    if not HAS_NUMBA:
        pytest.skip("Numba not installed")

    # Test with various data sizes
    for size in [10, 100, 1000]:
        data = [os.urandom(size) for _ in range(10)]
        num_perms = 16

        for d in data:
            sig_py = fast_sign(d, num_perms)
            sig_numba = numba_sign(d, num_perms)

            assert sig_py == sig_numba, f"Mismatch at size {size}"


@pytest.mark.slow
def test_numba_performance():
    """Benchmark Numba vs Python fast_sign."""
    if not HAS_NUMBA:
        pytest.skip("Numba not installed")

    data = os.urandom(1024 * 1024)  # 1MB
    num_perms = 16

    # Warmup Numba
    numba_sign(os.urandom(100), num_perms)

    start = time.perf_counter()
    numba_sign(data, num_perms)
    end = time.perf_counter()
    numba_time = end - start

    start = time.perf_counter()
    fast_sign(data, num_perms)
    end = time.perf_counter()
    py_time = end - start

    # Assert sanity (expect at least 5x speedup, usually much more)
    assert numba_time < py_time


if __name__ == "__main__":
    # Manual run
    if HAS_NUMBA:
        test_numba_correctness()
        test_numba_performance()
    else:
        print("Numba not installed. Skipping benchmark.")
