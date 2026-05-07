"""Radare2-style byte-level function signatures with bit-mask wildcarding."""

from typing import Self
from binrankbench.common.hex import HexValue, hexvalue_to_bytes

class ByteSignature:
    """Represents a radare2-style bit-level binary signature with a mask."""
    
    def __init__(self, raw_bytes: HexValue | bytes, mask: HexValue | bytes, cap_byte_size: int = 500, cc: int = 0):
        if not raw_bytes or not mask:
            raise ValueError("Raw bytes and mask must not be empty")
        
        # Utilize the provided conversion function
        b_bytes = raw_bytes if isinstance(raw_bytes, bytes) else hexvalue_to_bytes(raw_bytes)
        m_bytes = mask if isinstance(mask, bytes) else hexvalue_to_bytes(mask)
        
        if cap_byte_size > 0:
            b_bytes = b_bytes[:cap_byte_size]
            m_bytes = m_bytes[:cap_byte_size]
        
        if len(b_bytes) != len(m_bytes):
            raise ValueError(
                f"Raw bytes length ({len(b_bytes)}) must match mask length ({len(m_bytes)})"
            )

        self.mask = m_bytes
        self.length = len(b_bytes)
        self.cc = cc
        
        # Apply mask strictly upon initialization (Radare2 standard)
        self.bytes = bytes(b & m for b, m in zip(b_bytes, m_bytes))

    def __str__(self) -> str:
        """Returns a human-readable representation of the signature."""
        res = []
        for b, m in zip(self.bytes, self.mask):
            if m == 0xFF:
                res.append(f"{b:02x}")
            elif m == 0x00:
                res.append("..")
            else:
                res.append(f"[{b:02x}&{m:02x}]")
        return "".join(res)

    @staticmethod
    def compare(sig_a: 'ByteSignature', sig_b: 'ByteSignature', min_size: int = 16, min_cc: int = 10, mode: str = "density") -> float:
        """
        Calculates the similarity score between two signatures.
        
        Args:
            sig_a, sig_b: ByteSignature objects.
            min_size: Minimum absolute bytes of shared invariant bits required (Radare2 default 16).
            min_cc: Minimum cyclomatic complexity required for both functions.
            mode: "density" (normalized by max length) or "ratio" (normalized by intersection size).
        """
        if sig_a.cc < min_cc or sig_b.cc < min_cc:
            return 0.0

        max_len = max(sig_a.length, sig_b.length)
        if max_len == 0:
            return 0.0

        matching_bits = 0
        total_intersect_bits = 0
        
        for b_a, m_a, b_b, m_b in zip(sig_a.bytes, sig_a.mask, sig_b.bytes, sig_b.mask):
            common_mask = m_a & m_b
            if common_mask == 0:
                continue

            # Byte-level: the masked bytes either match or they don't
            if (b_a & common_mask) == (b_b & common_mask):
                matching_bits += common_mask.bit_count()
            total_intersect_bits += common_mask.bit_count()
                
        # Entropy check: must match at least min_size bytes (8 bits per byte)
        if matching_bits < (min_size * 8):
            return 0.0

        if mode == "ratio":
            return matching_bits / total_intersect_bits if total_intersect_bits > 0 else 0.0
        else: # density
            return (matching_bits / 8.0) / max_len

def compare_signatures(sig_a: ByteSignature, sig_b: ByteSignature) -> float:
    return ByteSignature.compare(sig_a, sig_b)