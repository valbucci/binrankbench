import pytest
from typing import Iterator

from binrankbench.common.hex import HexStr
from binrankbench.modules.catalog1 import Catalog1, Catalog1Error
from binrankbench.common.types import BIN2ML_CFG


def stream_function_hashes(bin2ml_data: BIN2ML_CFG, use_fast_sign=False
                           ) -> Iterator[Catalog1]:
    for (fcode_data,) in bin2ml_data:
        try:
            yield Catalog1.from_fcode(fcode_data, use_fast_sign=use_fast_sign)
        except Catalog1Error:
            continue


@pytest.mark.parametrize("bin2ml_data_path", ["cfg"], indirect=True)
def test_from_fcode(bin2ml_data: BIN2ML_CFG):
    fcode1 = bin2ml_data[0][0]
    hash1 = Catalog1.from_fcode(fcode1)
    HexStr.validate(hash1.digest)

@pytest.mark.parametrize("bin2ml_data_path", ["bytes-masked", "bytes"], 
                         indirect=True)
def test_from_fbytes(bin2ml_data):
    bin2ml_data_list = list(bin2ml_data.values())
    fbytes1 = bin2ml_data_list[0]
    fbytes2 = bin2ml_data_list[1]
    
    hash1 = Catalog1.from_hexvalue(fbytes1, byte_size=16)
    hash2 = Catalog1.from_hexvalue(fbytes2, byte_size=16)

    HexStr.validate(hash1.digest)
    HexStr.validate(hash2.digest)
    assert 0 <= hash1.similarity(hash2) <= 1

@pytest.mark.parametrize("bin2ml_data_path", ["cfg"], indirect=True)
def test_fast_sign(bin2ml_data):
    stream_slow = stream_function_hashes(bin2ml_data, use_fast_sign=False)
    stream_fast = stream_function_hashes(bin2ml_data, use_fast_sign=True)
    for hash1, hash2 in zip(stream_slow, stream_fast):
        assert hash1.similarity(hash2) == 1
        
        
