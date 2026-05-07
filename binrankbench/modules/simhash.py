"""SimHash implementation for accumulating hex values.

This module provides a SimHasher class that implements a similarity hashing
algorithm. It accumulates multiple hex values by tracking bit-level statistics
and produces a final hash that represents the "average" of all input values.
"""

from typing import Iterable

from binrankbench.common.hex import HexStr, HexInt, HexValue, hexvalue_to_bytes


class SimHasher:
    """A similarity hasher that accumulates hex values using bit-level statistics.
    
    The SimHasher uses a technique where each bit position is tracked with
    an accumulator. For each input value:
    - If a bit is 1, the accumulator for that position is incremented
    - If a bit is 0, the accumulator for that position is decremented
    
    The final hash is computed by setting each bit to 1 if its accumulator >= 0,
    otherwise 0.
    
    Example:
        >>> hasher = SimHasher(bytes_size=4)
        >>> hasher.add(HexStr("0x1234"))
        >>> hasher.update([HexStr("0x5678"), HexStr("0x9abc")])
        >>> result = hasher.digest()
        >>> print(hex(result))
    """
    
    def __init__(self, bytes_size: int = 8):
        """Initialize a SimHasher with a fixed byte size.
        
        Args:
            bytes_size: The number of bytes for the hash output. All input values
                will be padded to this length. Default is 8.
                
        Raises:
            ValueError: If bytes_size is less than 1.
        """
        if bytes_size < 1:
            raise ValueError(f"bytes_size must be at least 1, got {bytes_size}")
        
        self.bytes_size = bytes_size
        self.bit_count = bytes_size * 8
        self.accumulator = [0.0] * self.bit_count
    
    def _hexvalue_to_bytes(self, value: HexValue) -> bytes:
        """Convert a HexValue to bytes, handling all supported types.
        
        Args:
            value: A HexValue (str, int, bytes, HexStr, or HexInt).
            
        Returns:
            The value as bytes, padded to bytes_size.
        """
        if isinstance(value, HexStr):
            # HexStr has a working __bytes__ method
            b = bytes(value)
        elif isinstance(value, HexInt):
            # HexInt needs to be converted to int, then to bytes
            # Calculate how many bytes are needed
            int_val = int(value)
            if int_val == 0:
                b = b'\x00'
            else:
                # Calculate minimum bytes needed
                byte_length = (int_val.bit_length() + 7) // 8
                b = int_val.to_bytes(byte_length, byteorder='big')
        elif isinstance(value, bytes):
            b = value
        elif isinstance(value, int):
            # Calculate how many bytes are needed
            if value == 0:
                b = b'\x00'
            else:
                byte_length = (value.bit_length() + 7) // 8
                b = value.to_bytes(byte_length, byteorder='big')
        elif isinstance(value, str):
            # Convert string via HexStr to handle '0x' prefix properly
            b = bytes(HexStr(value))
        else:
            # Fallback: try to convert via hexvalue_to_bytes
            b = hexvalue_to_bytes(value)
        
        # Pad to the right length (left-pad with zeros)
        if len(b) < self.bytes_size:
            b = b.rjust(self.bytes_size, b'\x00')
        elif len(b) > self.bytes_size:
            # Truncate if longer (keep the rightmost bytes)
            b = b[-self.bytes_size:]
        
        return b
    
    def _accumulate_bits(self, data: bytes, weight: float = 1.0) -> None:
        """Accumulate the bits from a byte string into the accumulator.
        
        Args:
            data: The byte string to accumulate. Must be exactly bytes_size long.
        """
        if len(data) != self.bytes_size:
            raise ValueError(f"Expected {self.bytes_size} bytes, got {len(data)}")
        
        for i in range(self.bit_count):
            byte_index = i // 8
            bit_index = 7 - (i % 8)  # MSB first
            bit = (data[byte_index] >> bit_index) & 1
            
            if bit == 1:
                self.accumulator[i] += weight
            else:
                self.accumulator[i] -= weight
    
    def add(self, value: HexValue, weight: float = 1.0) -> None:
        """Add a single hex value to the accumulator.
        
        Args:
            value: A HexValue to add (str, int, bytes, HexStr, HexInt, or HexOffset).
            weight: Weight for this value (default 1.0).
        """
        b = self._hexvalue_to_bytes(value)
        self._accumulate_bits(b, weight)
    
    def update(self, values: Iterable[HexValue]) -> None:
        """Add multiple hex values to the accumulator.
        
        Args:
            values: An iterable of HexValue objects to add.
        """
        for value in values:
            self.add(value)
    
    def digest(self) -> bytes:
        """Compute and return the final hash as bytes.
        
        Returns:
            The final hash as a bytes object of length bytes_size.
        """
        # Collapse accumulator: bit is 1 if accumulator >= 0, else 0
        final_bits = ['1' if value >= 0 else '0' for value in self.accumulator]
        final_binstr = ''.join(final_bits)
        
        # Convert binary string to integer
        int_value = int(final_binstr, 2)
        
        # Convert to bytes
        return int_value.to_bytes(self.bytes_size, byteorder='big')
    
    def hexdigest(self) -> HexStr:
        """Compute and return the final hash as a HexStr.
        
        Returns:
            The final hash as a HexStr object.
        """
        digest_bytes = self.digest()
        return HexStr.from_bytes(digest_bytes)
    
    def reset(self) -> None:
        """Reset the accumulator to zero, clearing all previously added values."""
        self.accumulator = [0.0] * self.bit_count

