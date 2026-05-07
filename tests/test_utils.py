import pytest
from binrankbench.common.utils import get_address, set_address, is_address_set, is_address_placeholder, ADDR_SENTINEL

def test_is_address_placeholder():
    assert is_address_placeholder(None) is True
    assert is_address_placeholder(ADDR_SENTINEL) is True
    assert is_address_placeholder(0x400000) is False
    assert is_address_placeholder(0) is False

def test_get_address():
    data_offset = {"offset": 0x1000}
    assert get_address(data_offset) == 0x1000
    
    data_addr = {"addr": 0x2000}
    assert get_address(data_addr) == 0x2000
    
    with pytest.raises(ValueError):
        get_address({})

def test_set_address():
    data = {"offset": 0x1000}
    set_address(data, 0x5000)
    assert data["offset"] == 0x5000
    
    data = {"addr": 0x2000}
    set_address(data, 0x6000)
    assert data["addr"] == 0x6000

def test_is_address_set():
    # Logic in code seemed inverted: verified here
    
    # Case 1: Valid address -> Should be True (address IS set)
    data_valid = {"offset": 0x400000}
    
    # Case 2: Placeholder -> Should be False (address is NOT set/valid)
    data_placeholder = {"offset": ADDR_SENTINEL}
    
    # Case 3: Missing -> Should be False
    data_missing = {}
    
    # Asserting correct behavior (fails if code is buggy)
    assert is_address_set(data_valid) is True
    assert is_address_set(data_placeholder) is False
    assert is_address_set(data_missing) is False
