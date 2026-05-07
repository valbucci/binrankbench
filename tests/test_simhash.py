"""Tests for the SimHasher class."""

import pytest
from binrankbench.modules.simhash import SimHasher
from binrankbench.common.hex import HexStr, HexInt, HexOffset


class TestSimHasher:
    """Test cases for SimHasher."""
    
    def test_init(self):
        """Test SimHasher initialization."""
        hasher = SimHasher(bytes_size=4)
        assert hasher.bytes_size == 4
        assert hasher.bit_count == 32
        assert len(hasher.accumulator) == 32
        assert all(v == 0.0 for v in hasher.accumulator)
        
        # Test default bytes_size
        hasher_default = SimHasher()
        assert hasher_default.bytes_size == 8
        
        # Test invalid bytes_size
        with pytest.raises(ValueError, match="bytes_size must be at least 1"):
            SimHasher(bytes_size=0)
        
        with pytest.raises(ValueError, match="bytes_size must be at least 1"):
            SimHasher(bytes_size=-1)
    
    def test_accumulate_prototype_example(self):
        """Test that SimHasher matches the prototype accumulation algorithm."""
        # This is the exact example from test_hex.py test_accumulate
        bin_a = bytes(HexStr("0x00000000"))
        bin_b = bytes(HexStr("0x00000001"))
        bin_c = bytes(HexStr("0x10000000"))
        bin_d = bytes(HexStr("0x99999999"))
        
        inputs = [bin_a, bin_b, bin_c, bin_d]
        n_bytes = max(len(b) for b in inputs)
        bin_inputs = [b.rjust(n_bytes, b'\x00') for b in inputs]
        
        accumulator = [0] * (n_bytes * 8)
        
        for b in bin_inputs:
            for i in range(len(b) * 8):
                byte_index = i // 8
                bit_index = 7 - (i % 8)
                bit = (b[byte_index] >> bit_index) & 1
                if bit == 1:
                    accumulator[i] += 1
                else:
                    accumulator[i] -= 1
        
        # Collapse accumulator and build final binary string
        final_bits = ['1' if value >= 0 else '0' for value in accumulator]
        final_binstr = ''.join(final_bits)
        int_value = int(final_binstr, 2)
        hexlen = (len(final_binstr) + 3) // 4
        expected_hex = '0x' + f'{int_value:0{hexlen}x}'
        
        # Now test with SimHasher
        hasher = SimHasher(bytes_size=4)
        hasher.add(HexStr("0x00000000"))
        hasher.add(HexStr("0x00000001"))
        hasher.add(HexStr("0x10000000"))
        hasher.add(HexStr("0x99999999"))
        result = hasher.hexdigest()
        
        # Compare integer values (should match)
        assert int(result) == int_value, \
            f"Expected {int_value} (0x{int_value:x}), got {int(result)} (0x{int(result):x})"
    
    def test_add_single_value(self):
        """Test adding a single value."""
        hasher = SimHasher(bytes_size=4)
        hasher.add(HexStr("0x12345678"))
        result = hasher.hexdigest()
        # With only one value, result should match the input
        assert result == HexStr("0x12345678")
    
    def test_add_multiple_values(self):
        """Test adding multiple values with add()."""
        hasher = SimHasher(bytes_size=2)
        hasher.add(HexStr("0x0000"))
        hasher.add(HexStr("0x0001"))
        hasher.add(HexStr("0x0001"))
        # Two 0x0001 and one 0x0000 should result in 0x0001
        result = hasher.hexdigest()
        assert result == HexStr("0x0001")
    
    def test_update(self):
        """Test update() method with multiple values."""
        hasher = SimHasher(bytes_size=4)
        values = [
            HexStr("0x00000000"),
            HexStr("0x00000001"),
            HexStr("0x10000000"),
            HexStr("0x99999999")
        ]
        hasher.update(values)
        result = hasher.hexdigest()
        # Should produce the same result as adding individually
        assert isinstance(result, HexStr)
        assert len(result) > 0
    
    def test_update_vs_add(self):
        """Test that update() produces the same result as multiple add() calls."""
        hasher1 = SimHasher(bytes_size=4)
        hasher1.add(HexStr("0x1234"))
        hasher1.add(HexStr("0x5678"))
        hasher1.add(HexStr("0x9abc"))
        
        hasher2 = SimHasher(bytes_size=4)
        hasher2.update([HexStr("0x1234"), HexStr("0x5678"), HexStr("0x9abc")])
        
        assert hasher1.hexdigest() == hasher2.hexdigest()
        assert hasher1.digest() == hasher2.digest()
    
    def test_different_hex_types(self):
        """Test that SimHasher works with different HexValue types."""
        hasher = SimHasher(bytes_size=4)
        
        # Test with different types
        hasher.add(HexStr("0x1234"))
        hasher.add(HexInt("0x5678"))
        hasher.add(HexOffset("0x9abc"))
        hasher.add("0xdef0")  # str
        hasher.add(0x1111)  # int
        hasher.add(b'\x22\x22')  # bytes
        
        result = hasher.hexdigest()
        assert isinstance(result, HexStr)
        assert len(result) > 0
    
    def test_padding(self):
        """Test that values are properly padded to bytes_size."""
        hasher = SimHasher(bytes_size=8)
        
        # Add a small value that needs padding
        hasher.add(HexStr("0x1234"))
        result = hasher.digest()
        
        # Result should be exactly bytes_size long
        assert len(result) == 8
        
        # The value should be left-padded with zeros
        hasher2 = SimHasher(bytes_size=8)
        hasher2.add(HexStr("0x1234"))
        result2 = hasher2.hexdigest()
        # Should be equivalent to 0x0000000000001234
        assert int(result2) == 0x1234
    
    def test_truncation(self):
        """Test that values longer than bytes_size are truncated."""
        hasher = SimHasher(bytes_size=2)
        
        # Add a value longer than 2 bytes
        hasher.add(HexStr("0x12345678"))
        result = hasher.digest()
        
        # Result should be exactly 2 bytes (rightmost bytes kept)
        assert len(result) == 2
        # Should be 0x5678 (rightmost 2 bytes)
        assert result == b'\x56\x78'
    
    def test_reset(self):
        """Test reset() method."""
        hasher = SimHasher(bytes_size=4)
        hasher.add(HexStr("0x12345678"))
        hasher.add(HexStr("0x87654321"))
        
        # Get initial result
        result1 = hasher.hexdigest()
        
        # Reset and add different values
        hasher.reset()
        assert all(v == 0.0 for v in hasher.accumulator)
        
        hasher.add(HexStr("0x11111111"))
        result2 = hasher.hexdigest()
        
        # Results should be different
        assert result1 != result2
        assert result2 == HexStr("0x11111111")
    
    def test_digest_vs_hexdigest(self):
        """Test that digest() and hexdigest() return equivalent values."""
        hasher = SimHasher(bytes_size=4)
        hasher.add(HexStr("0x12345678"))
        hasher.add(HexStr("0x87654321"))
        
        digest_bytes = hasher.digest()
        hexdigest_str = hasher.hexdigest()
        
        # They should represent the same value
        assert digest_bytes == bytes(hexdigest_str)
        assert hexdigest_str == HexStr.from_bytes(digest_bytes)
    
    def test_empty_hasher(self):
        """Test that an empty hasher produces all ones (since 0 >= 0)."""
        hasher = SimHasher(bytes_size=4)
        result = hasher.digest()
        # When accumulator is all zeros, condition "value >= 0" is True for all bits
        # so result is all ones
        assert result == b'\xff' * 4
        
        result_hex = hasher.hexdigest()
        assert result_hex == HexStr("0xFFFFFFFF")
    
    def test_symmetric_values(self):
        """Test that symmetric values cancel out appropriately."""
        hasher = SimHasher(bytes_size=2)
        
        # Add 0x0000 and 0xFFFF (opposites)
        hasher.add(HexStr("0x0000"))
        hasher.add(HexStr("0xFFFF"))
        
        result = hasher.hexdigest()
        # With one of each, accumulator should be all zeros, so result is 0x0000
        assert result == HexStr("0xFFFF")
    
    def test_majority_wins(self):
        """Test that majority of values determines the result."""
        hasher = SimHasher(bytes_size=1)
        
        # Add 0x00 three times and 0xFF once
        hasher.add(HexStr("0x00"))
        hasher.add(HexStr("0x00"))
        hasher.add(HexStr("0x00"))
        hasher.add(HexStr("0xFF"))
        
        result = hasher.hexdigest()
        # Majority is 0x00, so result should be 0x00
        assert result == HexStr("0x00")
        
        # Now add one more 0xFF to make it 2-2
        hasher.add(HexStr("0xFF"))
        result2 = hasher.hexdigest()
        # With 2-2, accumulator should be all zeros, so result is 0x00
        assert result2 == HexStr("0x00")
        
        # Add one more 0xFF to make it 3-2
        hasher.add(HexStr("0xFF"))
        result3 = hasher.hexdigest()
        # Now majority is 0xFF, so result should be 0xFF
        assert result3 == HexStr("0xFF")

