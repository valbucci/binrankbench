"""Hex value types and conversion utilities for binary address and digest handling."""

from typing import Self, Union

from binrankbench.common.logging import LOGGER as base_logger

logger = base_logger.getChild("hex")

HexValue = Union[str, int, bytes, "HexStr", "HexInt"]


#region CONVERSIONS
def hexvalue_to_int(value: HexValue) -> int:
    logger.debug(f"Converting {value!r} to integer")
    if isinstance(value, int):
        return value
    elif isinstance(value, str):
        return int(HexStr(value))
    elif isinstance(value, bytes):
        return int.from_bytes(value)
    else:
        logger.error(f"Tried to convert {value!r} to integer")
        raise NotImplementedError(f"Unsupported type: {type(value)}")


def hexvalue_to_str(value: HexValue) -> str:
    logger.debug(f"Converting {value!r} to string")
    if isinstance(value, str):
        return value
    elif isinstance(value, int):
        return HexStr(value)
    elif isinstance(value, bytes):
        return HexStr.from_bytes(value)
    else:
        logger.error(f"Tried to convert {value!r} to string")
        raise NotImplementedError(f"Unsupported type: {type(value)}")


def hexvalue_to_bytes(value: HexValue) -> bytes:
    logger.debug(f"Converting {value!r} to bytes")
    if isinstance(value, bytes):
        return value
    elif isinstance(value, int):
        return value.to_bytes()
    elif isinstance(value, str):
        if len(value) % 2 == 1:
            value = f"0{value}"
        return bytes.fromhex(value)
    else:
        logger.error(f"Tried to convert {value!r} to bytes")
        raise NotImplementedError(f"Unsupported type: {type(value)}")
#endregion CONVERSIONS


#region BITMASKING
def fixup_bitmask_lengths(data: bytes, mask: bytes
                          ) -> tuple[bytes, bytes]:
    """Fixes up the lengths of the data and mask to be the same.
    
    Args:
        data: The data to fix up.
        mask: The mask to fix up.
        
    Returns:
        The fixed up data and mask such that the lengths are the same. The 
        length matching operation is always performed on the mask so as to avoid
        modifying the raw data.
    """
    data_len = len(data)
    mask_len = len(mask)
    if data_len == mask_len:
        logger.debug("Tried to fixup bitmask length but data and mask lengths" 
                     f"are the same: {data_len}")
        return data, mask
    
    if data_len < mask_len:
        # The data is shorter than the mask: truncate the trailing bytes of the 
        # mask to match the length of the data.
        mask = mask[:data_len]
    else:
        # The data is longer than the mask: pad the mask on the left with zeros 
        # to match the length of the data.
        mask = b'\x00' * (data_len - mask_len) + mask
    return data, mask
    

def apply_bitmask(data: HexValue, mask: HexValue, 
                  enforce_same_length: bool = True) -> bytes:
    """Applies a bitmask to the data.
    
    Args:
        data: The data to apply the bitmask to.
        mask: The bitmask to apply.
        assert_same_length: Whether to assert that the data and mask have the 
            same length. If True, will raise a ValueError if the lengths do not 
            match. Otherwise, it will log a warning and pad/truncate the data 
            and mask to the same length. Default is True.
        
    Returns:
        The result of the bitwise AND operation.
    """
    
    data_bytes = hexvalue_to_bytes(data)
    mask_bytes = hexvalue_to_bytes(mask)
    
    # Check if lengths match
    if len(data_bytes) != len(mask_bytes):
        if not enforce_same_length:
            logger.warning("Data and mask length mismatch: "
                           f"{len(data_bytes)} != {len(mask_bytes)}")
            data_bytes, mask_bytes = fixup_bitmask_lengths(data_bytes, 
                                                           mask_bytes)
        else:
            raise ValueError("Data and mask length mismatch: "
                             f"{len(data_bytes)} != {len(mask_bytes)}")
        
    # Perform bitwise AND
    return bytes(a & b for a, b in zip(data_bytes, mask_bytes))
#endregion BITMASKING

class HexStr(str): 
    def __new__(cls, value: HexValue) -> Self:
        if isinstance(value, HexStr):
            return super().__new__(cls, str(value))
        elif isinstance(value, str):
            validated = cls.validate(value)
            return super().__new__(cls, validated)
        elif isinstance(value, int):
            return cls.from_int(value)
        elif isinstance(value, bytes):
            return cls.from_bytes(value)
        else:
            logger.error(
                f"Tried to create {cls.__name__} from object: {value!r}")
            raise ValueError(f"Unsupported type: {type(value)}")

    def __len__(self) -> int:
        return len(str(self))
    
    def __str__(self) -> str:
        return super().__str__().upper()
    
    def __int__(self) -> int:
        return int(self, 16)
    
    def __xor__(self, other: HexValue) -> Self:
        if len(self) != len(HexStr(other)):
            logger.debug(f"HexStr length mismatch: "
                           f"{len(self)} != {len(HexStr(other))}")
        return self.__class__(int(self) ^ int(HexStr(other)))
    
    def __and__(self, other: HexValue) -> Self:
        if len(self) != len(HexStr(other)):
            logger.debug(f"HexStr length mismatch: "
                           f"{len(self)} != {len(HexStr(other))}")
        return self.__class__(int(self) & int(HexStr(other)))
    
    def __or__(self, other: HexValue) -> Self:
        if len(self) != len(HexStr(other)):
            logger.debug(f"HexStr length mismatch: "
                           f"{len(self)} != {len(HexStr(other))}")
        return self.__class__(int(self) | int(HexStr(other)))
    
    def __bytes__(self) -> bytes:
        if len(self) % 2 == 1:
            return bytes.fromhex(f"0{self}")
        return bytes.fromhex(self)
    
    def __index__(self) -> int:
        return self.__int__()
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}('{super().__str__()}')"
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, HexStr):
            # Compare values, not strings (e.g. "1234" == "001234")
            return self.__int__() == other.__int__()
        elif isinstance(other, str):
            try:
                return self == HexStr(other)
            except ValueError:
                logger.warning(f"Tried non-hex comparison {self!r} == {other!r}")
                return False
        elif isinstance(other, int):
            return self.__int__() == other
        elif isinstance(other, bytes):
            return self == HexStr.from_bytes(other)
        else:
            logger.warning(f"Tried unsupported comparison {self!r} == {other!r}")
            raise NotImplementedError(f"Unsupported comparison: {type(other)}")
        
    def __lt__(self, other: object) -> bool:
        if isinstance(other, HexStr):
            return self.__int__() < other.__int__()
        elif isinstance(other, str):
            try:
                return self < HexStr(other)
            except ValueError:
                logger.warning(f"Tried non-hex comparison {self!r} < {other!r}")
                return False
        elif isinstance(other, int):
            return self.__int__() < other
        elif isinstance(other, bytes):
            return self.__int__() < int.from_bytes(other)
        else:
            logger.warning(f"Tried unsupported comparison {self!r} < {other!r}")
            raise NotImplementedError(f"Unsupported comparison: {type(other)}")
    
    def __le__(self, other: object) -> bool:
        return self.__lt__(other) or self.__eq__(other)
    
    def __gt__(self, other: object) -> bool:
        return not self.__le__(other)
    
    def __ge__(self, other: object) -> bool:
        return not self.__lt__(other)
    
    def __hash__(self) -> int:
        return hash(self.__str__())

    @classmethod
    def from_bytes(cls, value: bytes) -> Self:
        return cls("".join(f"{b:02x}" for b in value))
    
    @classmethod
    def from_int(cls, value: int) -> Self:
        return cls(hex(value).removeprefix("0x"))
    
    @classmethod
    def is_valid(cls, value: str) -> bool:
        return len(value) > 0 and all(c in "0123456789ABCDEF" for c in value)
    
    @classmethod
    def validate(cls, value: str) -> str:
        clean_value = value.removeprefix("0x").upper()
        if not cls.is_valid(clean_value):
            raise ValueError("HexStr must be a valid hexadecimal string, "
                             f"got {value!r}")
        return clean_value
    
    def is_equal(self, other: HexValue) -> bool:
        is_equal = False
        try:
            is_equal = self.__str__() == HexStr(other).__str__()
        except ValueError:
            logger.warning(
                "Tried to compare HexStr with non-hex string: %r", other)
        except Exception as e:
            logger.error(f"Tried to compare HexStr with {other!r}: {e}")

        return is_equal


class Nibble(HexStr):
    def __bytes__(self) -> bytes:
        raise ValueError("Nibble cannot be converted to bytes")
    
    @classmethod
    def from_bytes(cls, value: bytes) -> Self:
        hex_str = HexStr.from_bytes(value)
        if len(hex_str.lstrip("0")) > 1:
            raise ValueError(
                "Cannot convert bytes to Nibble: would lose information")
        return cls(hex_str[-1])
    
    @classmethod
    def is_valid(cls, value: str) -> bool:
        return len(value) == 1 and value in "0123456789ABCDEF"
    
    @classmethod
    def validate(cls, value: str) -> str:
        clean_value = value.removeprefix("0x").upper()
        if not cls.is_valid(clean_value):
            raise ValueError("Nibble must be a single hexadecimal character, "
                             f"got {value!r}")
        return clean_value
    
    
class HexInt(int):
    def __new__(cls, value: HexValue) -> Self:
        if isinstance(value, HexStr):
            return super().__new__(cls, int(value))
        elif isinstance(value, int):
            return super().__new__(cls, value)
        elif isinstance(value, str) or isinstance(value, bytes):
            return super().__new__(cls, int(HexStr(value)))
        else:
            logger.error(
                f"Tried to create {cls.__name__} from object: {value!r}")
            raise ValueError(f"Unsupported type: {type(value)}")
        
    def __hash__(self) -> int:
        return hash(self.__int__())
    
    def __bytes__(self) -> bytes:
        return self.to_bytes()
        
    def __str__(self) -> str:
        return f"0x{self:x}"
    
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self})"
    
    def __eq__(self, other: object) -> bool:
        if isinstance(other, int):
            return self.__int__() == other
        elif isinstance(other, str) or isinstance(other, bytes):
            return self.__int__() == int(HexStr(other))
        else:
            logger.warning(f"Tried unsupported comparison {self!r} == {other!r}")
            raise NotImplementedError(f"Unsupported comparison: {type(other)}")
        
    def __lt__(self, other: object) -> bool:
        if isinstance(other, int):
            return self.__int__() < other
        elif isinstance(other, str) or isinstance(other, bytes):
            return self.__int__() < int(HexStr(other))
        else:
            logger.warning(f"Tried unsupported comparison {self!r} < {other!r}")
            raise NotImplementedError(f"Unsupported comparison: {type(other)}")
        
    def __le__(self, other: object) -> bool:
        return self.__lt__(other) or self.__eq__(other)
    
    def __gt__(self, other: object) -> bool:
        return not self.__le__(other)
    
    def __ge__(self, other: object) -> bool:
        return not self.__lt__(other)
    
    def __add__(self, other: HexValue) -> Self:
        other = hexvalue_to_int(other)
        return self.__class__(int(self) + other)
    
    def __sub__(self, other: HexValue) -> Self:
        other = hexvalue_to_int(other)
        return self.__class__(int(self) - other)
    
    def __xor__(self, other: HexValue) -> Self:
        other = hexvalue_to_int(other)
        return self.__class__(int(self) ^ other)
    
    def __and__(self, other: HexValue) -> Self:
        other = hexvalue_to_int(other)
        return self.__class__(int(self) & other)
    
    def __or__(self, other: HexValue) -> Self:
        other = hexvalue_to_int(other)
        return self.__class__(int(self) | other)

    
class HexOffset(HexInt):
    def __new__(cls, value: HexValue) -> Self:
        return super().__new__(cls, value)
        
    def __hash__(self) -> int:
        return self.__int__()
    
