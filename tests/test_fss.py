import pytest
import copy
from pathlib import Path

from binrankbench.modules.fss import split_disasm, FunctionSimSearch


@pytest.fixture
def fss_weights_path(data_dir) -> Path:
    return data_dir / "fss_weights.txt"


def test_split_disasm():
    disasm = "mov rsi, qword [0x00681068]"
    expected = ("mov", "rsi", "qword", "[0x00681068]")
    assert split_disasm(disasm) == expected


class TestFunctionSimSearch:
    
    def test_str_is_32_chars(self):
        hash = FunctionSimSearch(0xFEDCBA9876543210, 0x1234567890ABCDEF)
        assert len(str(hash)) == 32
    
    def test_first_and_second(self):
        hash = FunctionSimSearch(0xFEDCBA9876543210, 0x1234567890ABCDEF)
        assert hash.first == 0xFEDCBA9876543210
        assert hash.second == 0x1234567890ABCDEF
        assert hash.value == 0xFEDCBA98765432101234567890ABCDEF
        
    def test_from_value(self):
        hash = FunctionSimSearch.from_value(0xFEDCBA987654321001234567890ABCDE)
        assert hash.first == 0xFEDCBA9876543210
        assert hash.second == 0x01234567890ABCDE
        assert hash.value == 0xFEDCBA987654321001234567890ABCDE
        
    def test_eq(self):
        hash1 = FunctionSimSearch(0xFEDCBA9876543210, 0x1234567890ABCDEF)
        hash2 = FunctionSimSearch(0xFEDCBA9876543210, 0x1234567890ABCDEF)
        assert hash1 == hash2
        
        hash3 = FunctionSimSearch(0xFEDCBA9876543210, 0x1234567890ABCDE0)
        assert hash1 != hash3
        
    def test_bytes(self):
        hash = FunctionSimSearch(0xFEDCBA9876543210, 0x1234567890ABCDEF)
        assert hash.as_bytes == bytes(hash)
        assert hash.as_bytes == bytes.fromhex("FEDCBA98765432101234567890ABCDEF")
        assert hash.as_bytes == FunctionSimSearch.fromhex(
            "FEDCBA98765432101234567890ABCDEF").as_bytes
        
    def test_hash(self):
        hash = FunctionSimSearch(0xFEDCBA9876543210, 0x1234567890ABCDEF)
        assert hash.__hash__() == 0xFEDCBA98765432101234567890ABCDEF
        
        hash2 = FunctionSimSearch(0xFEDCBA9876543210, 0x1234567890ABCDE0)
        hash_copy = FunctionSimSearch(0xFEDCBA9876543210, 0x1234567890ABCDEF)
        hash_missing = FunctionSimSearch(0xFEDCBA9876543210, 0x1234567890ABCDE1)
        
        test_dict = {hash: "value", hash2: "value2"}
        
        assert hash in test_dict
        assert hash2 in test_dict
        assert hash_copy in test_dict
        assert hash_missing not in test_dict
        
        assert test_dict[hash] == "value"
        assert test_dict[hash_copy] == "value"
        assert test_dict[hash2] == "value2"
        with pytest.raises(KeyError):
            test_dict[hash_missing]
        
    def test_iter(self):
        hash = FunctionSimSearch(0xFEDCBA9876543210, 0x1234567890ABCDEF)
        assert list(hash) == [0xFEDCBA9876543210, 0x1234567890ABCDEF]
        assert tuple(hash) == (0xFEDCBA9876543210, 0x1234567890ABCDEF)
        
    def test_copy(self):
        from copy import copy

        orig = FunctionSimSearch(0x1234, 0xABCD)
        dup1 = copy(orig)
        dup2 = orig.copy()

        assert dup1 == orig
        assert dup2 == orig
        assert dup1 == dup2
        assert dup1 is not orig
        assert dup2 is not orig
        assert dup1 is not dup2
        
    def test_from_bytes(self):
        hash = FunctionSimSearch.from_bytes(
            b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
        )
        assert hash.first == 0x0001020304050607
        assert hash.second == 0x08090A0B0C0D0E0F
        assert hash.value == 0x000102030405060708090A0B0C0D0E0F
        
        with pytest.raises(ValueError):
            FunctionSimSearch.from_bytes(
                b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
                b"\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F"
                b"\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F"
            )
            
        hash_short = FunctionSimSearch.from_bytes(b"\x10")
        assert hash_short.first == 0x0000000000000000
        assert hash_short.second == 0x0000000000000010
        assert hash_short.value == 0x00000000000000000000000000000010
        
        hash_empty = FunctionSimSearch.from_bytes(b"")
        assert hash_empty.first == 0x0000000000000000
        assert hash_empty.second == 0x0000000000000000
        assert hash_empty.value == 0x00000000000000000000000000000000
        
    def test_fromhex(self):
        hash = FunctionSimSearch.fromhex("0x1234567890ABCDEF01234567890ABCDE")
        assert hash.first == 0x1234567890ABCDEF
        assert hash.second == 0x01234567890ABCDE
        assert hash.value == 0x1234567890ABCDEF01234567890ABCDE
        
    def test_fromhexpair(self):
        hash = FunctionSimSearch.fromhexpair("1234567890ABCDEF", "01234567890ABCDE")
        assert hash.first == 0x1234567890ABCDEF
        assert hash.second == 0x01234567890ABCDE
        assert hash.value == 0x1234567890ABCDEF01234567890ABCDE
        
        with pytest.raises(ValueError):
            FunctionSimSearch.fromhexpair("1234567890ABCDEFFF",
                                          "01234567890ABCDE0")
        
        hash_short = FunctionSimSearch.fromhexpair("123", "ABC")
        assert hash_short.first == 0x0000000000000123
        assert hash_short.second == 0x0000000000000ABC
        assert hash_short.value == 0x00000000000001230000000000000ABC
        
    def test_hamming_distance(self):
        hash1 = FunctionSimSearch(0x1234567890ABCDEF, 0xFEDCBA9876543210)
        hash2 = FunctionSimSearch(0x1234567890ABCDEF, 0xFEDCBA9876543210)
        assert hash1.hamming_distance(hash2) == 0
        
        hash3 = FunctionSimSearch(0x1234567890ABCDEF, 0x0EDCBA9876543210)
        assert hash3.hamming_distance(hash1) == 4

    def test_similarity(self):
        hash1 = FunctionSimSearch(0x1234567890ABCDEF, 0xFEDCBA9876543210)
        hash2 = FunctionSimSearch(0x1234567890ABCDEF, 0xFEDCBA9876543210)
        assert hash1.similarity(hash2) == 1
        
        hash3 = FunctionSimSearch(0x1234567890ABCDEF, 0x0EDCBA9876543210)
        assert hash3.similarity(hash1) >= 0.93
    
    def test_from_agfj(self, r2_agfj_data, fss_weights_path):
        hash_first = FunctionSimSearch.from_fcode(r2_agfj_data)
        
        # Make a copy and remove the last block to make slightly different hash
        agfj_copy = copy.deepcopy(r2_agfj_data)
        agfj_copy["blocks"] = agfj_copy["blocks"][:1]
        hash_second = FunctionSimSearch.from_fcode(agfj_copy)
        
        assert fss_weights_path.is_file()
        assert hash_first.value != hash_second.value
        assert 0 < hash_first.similarity(hash_second) < 1

    @pytest.mark.parametrize("bin2ml_data_path", ["cfg"], indirect=True)
    def test_from_bin2ml_cfg(self, bin2ml_data):
        for address, name, fss_hash in FunctionSimSearch.from_bin2ml_cfg(bin2ml_data):
            assert isinstance(address, int)
            assert isinstance(name, str)
            assert isinstance(fss_hash, FunctionSimSearch)
            
    def test_from_components(self):
        # Cisco-Talos hello.i64:0x7b0 — exact hash comparisons are in
        # test_regression.py::test_fss_marcelli_cisco_talos (regression-marked).
        # This test only verifies that the four weight configs produce mutually
        # consistent similarity scores.
        nodes = [1991, 2024, 1968, 2003, 2008, 1977]
        edges = [[1977, 2003], [1968, 2024], [1977, 1991], [2003, 2008],
                 [1991, 2003], [1968, 1977]]
        instructions = {
            "1991": [["mov", ["rdi", "[rip+2099258]"]], ["call", ["#0x6e0"]]],
            "2024": [["ret", []]],
            "1968": [["cmp", ["[rip+2099577]", "#0x0"]], ["jne", ["#0x7e8"]]],
            "2003": [["call", ["#0x720"]]],
            "2008": [["mov", ["[rip+2099537]", "#0x1"]], ["pop", ["rbp"]], ["ret", []]],
            "1977": [["cmp", ["[rip+2099215]", "#0x0"]], ["push", ["rbp"]],
                     ["mov", ["rbp", "rsp"]], ["je", ["#0x7d3"]]],
        }

        weights = [
            {"immediate_weight": 0.00, "mnem_weight": 0.00, "graphlet_weight": 1.00},
            {"immediate_weight": 0.00, "mnem_weight": 1.00, "graphlet_weight": 1.00},
            {"immediate_weight": 1.00, "mnem_weight": 1.00, "graphlet_weight": 1.00},
            {"immediate_weight": 4.00, "mnem_weight": 0.05, "graphlet_weight": 1.00},
        ]
        digests = [
            FunctionSimSearch.from_components(nodes, edges, instructions,
                                              mode="marcelli", marcelli_weights=w)
            for w in weights
        ]
        for i in range(len(digests) - 1):
            for j in range(i + 1, len(digests)):
                sim1 = digests[i].similarity(digests[j])
                sim2 = digests[j].similarity(digests[i])
                assert sim1 == sim2
                assert 0 < sim1 <= 1
