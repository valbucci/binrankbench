import pytest
from binrankbench.common.hex import HexStr, Nibble, HexOffset, HexInt


class TestHexStr:
    def test_validate(self):
        HexStr("0")
        HexStr("0x0")
        HexStr("0x1234")
        HexStr("1234")
        HexStr("0x01234")
        HexStr("0x0000000000000001234")
        HexStr(HexStr("0x1234"))
        
        # Invalid
        with pytest.raises(ValueError):
            HexStr("")
        with pytest.raises(ValueError):
            HexStr("0x")
        with pytest.raises(ValueError):
            HexStr("0x1234g")
            
    def test_int(self):
        assert int(HexStr("0x1234")) == 0x1234
        assert int(HexStr("0x01234")) == 0x1234
        assert int(HexStr("1234")) == 0x1234
        assert int(HexStr("01234")) == 0x1234
        
        assert HexStr(int(HexStr("0x00ff"))) == HexStr("0xff")
        
    def test_from_int(self):
        assert HexStr.from_int(0x1234) == HexStr("1234")
        assert HexStr.from_int(0x01234) == HexStr("1234")
        
    def test_bytes(self):
        assert bytes(HexStr("0x1234")) == b"\x12\x34"
        assert bytes(HexStr("1234")) == b"\x12\x34"
        assert bytes(HexStr("012345")) == b"\x01\x23\x45"
            
    def test_from_bytes(self):
        assert HexStr.from_bytes(b"\x12\x34") == HexStr("0x1234")
        assert HexStr.from_bytes(b"\x01\x23\x45") == HexStr("0x012345")
        
        with pytest.raises(ValueError):
            _ = HexStr.from_bytes(b"")
        
    def test_hex(self):
        assert hex(HexStr("0x1234")) == "0x1234"
        assert hex(HexStr("1234")) == "0x1234"
        assert hex(HexStr("01234")) == "0x1234"
        
    def test_repr(self):
        assert repr(HexStr("0x1234")) == "HexStr('1234')"
        assert repr(HexStr("1234")) == "HexStr('1234')"
        
    def test_str(self):
        assert str(HexStr("0x1234")) == "1234"
        assert str(HexStr("1234")) == "1234"
        assert str(HexStr("0x0000000001234")) != "1234"
        
    def test_eq(self):
        assert HexStr("0x1234") == HexStr("0x1234")
        assert HexStr("0x1234") == HexStr("1234")
        
        assert HexStr("0x1234") == "1234"
        assert HexStr("0x1234") == "0x1234"
        assert HexStr("0x1234") == 0x1234
        assert HexStr("0x01234") == 0x1234
        assert HexStr("0x1234") == b"\x12\x34"
        
        assert HexStr("0x0f") != Nibble("f")
        assert HexStr("0x1234") != HexStr("01234")
        assert HexStr("0x1234") != "1235"
        assert HexStr("0x1234") != 0x1235
        assert HexStr("0x1234") != b"\x12\x35"
        assert HexStr("0x1234") != Nibble("f")
        
    def test_is_equal(self):
        assert HexStr("0x1234").is_equal("0x1234")
        assert HexStr("0x1234").is_equal("1234") 
        assert not HexStr("0x1234").is_equal("0x01234")
        assert not HexStr("0x1234").is_equal("01234")
        assert not HexStr("0x1234").is_equal("abc")
        assert not HexStr("0").is_equal("")
        
    def test_compare(self):
        assert HexStr("0x1234") < HexStr("0x1235")
        assert HexStr("0x1234") > HexStr("0x1233")
        assert HexStr("0x1234") >= HexStr("0x1233")
        assert HexStr("0x1234") >= HexStr("0x1234")
        assert HexStr("0x1234") <= HexStr("0x1235")
        assert HexStr("0x1234") <= HexStr("0x1234")
        assert HexStr("0x1234") <= HexStr("0x01234")

        assert HexStr("0x1234") < 0x1235
        assert HexStr("0x1234") > 0x1233
        assert HexStr("0x1234") >= 0x1233
        assert HexStr("0x1234") >= 0x1234
        assert HexStr("0x1234") <= 0x1235
        assert HexStr("0x1234") <= 0x1234
        
        assert HexStr("0x1234") < b"\x12\x35"
        assert HexStr("0x1234") > b"\x12\x33"
        assert HexStr("0x1234") >= b"\x12\x33"
        assert HexStr("0x1234") >= b"\x12\x34"
        assert HexStr("0x1234") <= b"\x12\x35"
        assert HexStr("0x1234") <= b"\x12\x34"

    def test_xor(self):
        assert HexStr("0x1234") ^ HexStr("0x1235") == HexStr("0x0001")
        assert HexStr("0x1234") ^ HexStr("0x1233") == HexStr("0x0007")
        assert HexStr("0x1234") ^ HexStr("0x01234") == HexStr("0x0000")
        assert HexStr("0x1234") ^ HexStr("01234") == HexStr("0x0000")
        
        assert HexStr("0xffffff") ^ 0xff00ff == HexStr("0x00ff00")


    def test_and(self):
        assert HexStr("0x1234") & HexStr("0x1235") == HexStr("0x1234")
        assert HexStr("0x1234") & HexStr("0x1233") == HexStr("0x1230")
        assert HexStr("0x1234") & HexStr("0x01234") == HexStr("0x1234")
        assert HexStr("0x1234") & HexStr("01234") == HexStr("0x1234")
        
        assert HexStr("0xffffff") & 0xaa0011 == HexStr("0xaa0011")
        assert HexStr("ffffffff") & HexStr("ffff") == HexStr("0000ffff")


    def test_or(self):
        assert HexStr("0x1234") | HexStr("0x1235") == HexStr("0x1235")
        assert HexStr("0x1234") | HexStr("0x1233") == HexStr("0x1237")
        assert HexStr("0x1234") | HexStr("0x01234") == HexStr("0x1234")
        assert HexStr("0x1234") | HexStr("01234") == HexStr("0x1234")

        assert HexStr("0xffffff") | 0xaa0011 == HexStr("0xffffff")
        
        
    def test_accumulate(self):
        bin_a = bytes(HexStr("0x00000000"))
        bin_b = bytes(HexStr("0x00000001"))
        bin_c = bytes(HexStr("0x10000000"))
        bin_d = bytes(HexStr("0x99999999"))

        inputs = [bin_a, bin_b, bin_c, bin_d]
        n_bytes = max(len(b) for b in inputs)
        bin_inputs = [
            b.rjust(n_bytes, b'\x00') for b in inputs
        ]

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
        final_bits = [
            '1' if value >= 0 else '0' for value in accumulator
        ]
        final_binstr = ''.join(final_bits)
        int_value = int(final_binstr, 2)
        hexlen = (len(final_binstr) + 3) // 4
        expected_hex = '0x' + f'{int_value:0{hexlen}x}'


class TestNibble:
        
    def test_validate(self):
        Nibble("0")
        Nibble("f")
        Nibble("0x0")
        Nibble("0xf")
        with pytest.raises(ValueError):
            Nibble("0x1234")
        with pytest.raises(ValueError):
            Nibble("0xg")
        with pytest.raises(ValueError):
            Nibble("0x00")
            
    def test_eq(self):
        assert Nibble("0") == HexStr("0")
        assert Nibble("f") == HexStr("f")
        assert Nibble("0") == "0"
        assert Nibble("f") == "f"
        assert Nibble("0") == 0
        assert Nibble("f") == 15
        
        assert Nibble("0") != HexStr("000")
        assert Nibble("0") == b"\x00"
        assert not Nibble("0").is_equal("00")
            
    def test_from_int(self):
        assert Nibble.from_int(0) == Nibble("0")
        assert Nibble.from_int(15) == Nibble("f")
        
        with pytest.raises(ValueError):
            _ = Nibble.from_int(16)
            
    def test_bytes(self):
        with pytest.raises(ValueError):
            _ = bytes(Nibble("0"))
            
    def test_from_bytes(self):
        assert Nibble.from_bytes(b"\x00") == Nibble("0")
        assert Nibble.from_bytes(b"\x0f") == Nibble("f")
        
        with pytest.raises(ValueError):
            _ = Nibble.from_bytes(b"\xff")



class TestHexInt:
    def test_xor(self):
        assert HexInt("0x1234") ^ HexInt("0x1235") == HexInt("0x0001")
        assert HexInt("0x1234") ^ HexInt("0x1233") == HexInt("0x0007")
        assert HexInt("0x1234") ^ HexInt("0x01234") == HexInt("0x0000")
        assert HexInt("0x1234") ^ HexInt("01234") == HexInt("0x0000")

    def test_and(self):
        assert HexInt("0x1234") & HexInt("0x1235") == HexInt("0x1234")
        assert HexInt("0x1234") & HexInt("0x1233") == HexInt("0x1230")
        assert HexInt("0x1234") & HexInt("0x01234") == HexInt("0x1234")
        assert HexInt("0x1234") & HexInt("01234") == HexInt("0x1234")

    def test_or(self):
        assert HexInt("0x1234") | HexInt("0x1235") == HexInt("0x1235")
        assert HexInt("0x1234") | HexInt("0x1233") == HexInt("0x1237")
        assert HexInt("0x1234") | HexInt("0x01234") == HexInt("0x1234")
        assert HexInt("0x1234") | HexInt("01234") == HexInt("0x1234")


class TestHexOffset:
    
    def test_new(self):
        assert HexOffset("0x1234") == HexOffset(0x1234)
        assert HexOffset("1234") == HexOffset(0x1234)
        assert HexOffset("1234") == HexOffset(HexStr("0x00000000000001234"))
        assert HexOffset("1234") == HexOffset(b"\x12\x34")
        
        with pytest.raises(ValueError):
            _ = HexOffset(None) # type: ignore
        with pytest.raises(ValueError):
            _ = HexOffset("g")
        with pytest.raises(ValueError):
            _ = HexOffset(b"")
            
        
    def test_compare(self):
        assert HexOffset("0x1234") < HexOffset("0x1235")
        assert HexOffset("0x1234") > HexOffset("0x1233")
        assert HexOffset("0x1234") >= HexOffset("0x1233")
        assert HexOffset("0x1234") >= HexOffset("0x1234")
        assert HexOffset("0x1234") <= HexOffset("0x1235")
        assert HexOffset("0x1234") <= HexOffset("0x1234")
        
        assert HexOffset("0x1234") < 0x1235
        assert HexOffset("0x1234") > 0x1233
        assert HexOffset("0x1234") >= 0x1233
        assert HexOffset("0x1234") >= 0x1234
        assert HexOffset("0x1234") <= 0x1235
        assert HexOffset("0x1234") <= 0x1234
        
        assert HexOffset("0x1234") < b"\x12\x35"
        assert HexOffset("0x1234") > b"\x12\x33"
        assert HexOffset("0x1234") >= b"\x12\x33"
        assert HexOffset("0x1234") >= b"\x12\x34"
        assert HexOffset("0x1234") <= b"\x12\x35"
        assert HexOffset("0x1234") <= b"\x12\x34"
        
        assert HexOffset("0x1234") < "0x1235"
        assert HexOffset("0x1234") > "0x1233"
        assert HexOffset("0x1234") >= "0x1233"
        assert HexOffset("0x1234") >= "0x1234"
        assert HexOffset("0x1234") <= "0x1235"
        assert HexOffset("0x1234") <= "0x1234"
        
        with pytest.raises(NotImplementedError):
            _ = HexOffset("0x1234") < ["0", "1"]
            
            
        assert HexOffset("0x1234") == HexOffset("0x0000000001234")

    
    def test_hash(self):
        assert hash(HexOffset("0x1234")) == hash(0x1234)
        assert hash(HexOffset("1234")) == hash(0x1234)
        assert hash(HexOffset("1234")) == hash(HexOffset("0x00000000000001234"))
        assert hash(HexOffset("1234")) == hash(HexOffset(b"\x12\x34"))
        
        assert hash(HexOffset("1234")) != hash(b"\x12\x34")
        assert hash(HexOffset("1234")) != hash("0x00000000000001234")
        
        # Let's check if it can be used as a key in a dictionary
        test_offset = HexOffset("1234")
        test_dict = {}
        test_dict[test_offset] = "Initial"
        test_dict[0x1234] = "Changed"
        
        # Now we should have changed the value
        assert test_dict[test_offset] == "Changed"
        assert test_dict[test_offset] == test_dict[0x1234]
        
        # Let's try another one
        test_dict[HexOffset("0000000001234")] = "Changed Again"
        assert test_dict[test_offset] == "Changed Again"
        assert test_dict[test_offset] == test_dict[0x1234]
        
        assert test_dict[HexOffset("0x1234")] == "Changed Again"
        assert test_dict[HexOffset("1234")] == "Changed Again"
        assert test_dict[HexOffset("0000000001234")] == "Changed Again"
        assert test_dict[HexOffset(b"\x12\x34")] == "Changed Again"
        assert test_dict[0x1234] == "Changed Again"
        assert test_dict[4660] == "Changed Again"
