import os
import time
import numpy as np
import pytest
from binrankbench.modules.catalog1 import Catalog1, fast_sign, numba_sign, HAS_NUMBA

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


def test_numba_performance():
    """Benchmark Numba vs Python fast_sign."""
    if not HAS_NUMBA:
        pytest.skip("Numba not installed")
        
    data = os.urandom(1024 * 1024) # 1MB
    num_perms = 16
    
    print(f"\nBenchmarking 1MB blob with {num_perms} permutations...")
    
    # Warmup Numba
    numba_sign(os.urandom(100), num_perms)
    
    start = time.perf_counter()
    numba_sign(data, num_perms)
    end = time.perf_counter()
    numba_time = end - start
    print(f"Numba JIT time: {numba_time:.4f}s")
    
    start = time.perf_counter()
    fast_sign(data, num_perms)
    end = time.perf_counter()
    py_time = end - start
    print(f"Pure Python time: {py_time:.4f}s")
    
    speedup = py_time / numba_time
    print(f"Speedup: {speedup:.1f}x")
    
    # Assert sanity (expect at least 5x speedup, usually much more)
    assert numba_time < py_time

if __name__ == "__main__":
    # Manual run
    if HAS_NUMBA:
        test_numba_correctness()
        test_numba_performance()
    else:
        print("Numba not installed. Skipping benchmark.")
