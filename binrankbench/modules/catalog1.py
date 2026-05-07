"""
Catalog1 MinHash implementation (faithful to FCatalog design).

Usage:
    a = Catalog1("deadbeef00112233", byte_size=64)
    b = Catalog1("deadbeef00112234", byte_size=64)
    print(a.similarity(b))
"""

import struct
import numpy as np
from typing import Optional, Self

from binrankbench.common.hex import HexStr, HexValue, hexvalue_to_bytes
from binrankbench.common.types import R2CodeInfoIn

try:
    import numba
    from numba import njit, prange
    HAS_NUMBA = True
except ImportError:
    HAS_NUMBA = False
    njit = lambda *args, **kwargs: (lambda f: f)
    prange = range

#region PRIMITIVES

class Catalog1Error(Exception):
    """
    Exception for Catalog1 errors.
    """
    pass

#region -- Original Implementation from FCatalog --
# =================================================================== #
#   This region of code was copied from original immplementation at:
#              https://www.xorpd.net/pages/fcatalog.html
# =================================================================== #

WORD_BITSIZE = 32
WORD_BYTESIZE = WORD_BITSIZE // 8
MAX_WORD = (1 << WORD_BITSIZE) - 1

# An array of random dwords (length 128).
RAND_DWORDS = [1445200656, 3877429363, 1060188777, 4260769784, 1438562000,
    2836098482, 1986405151, 4230168452, 380326093, 2859127666, 1134102609,
    788546250, 3705417527, 1779868252, 1958737986, 4046915967, 1614805928,
    4160312724, 3682325739, 534901034, 2287240917, 2677201636, 71025852,
    1171752314, 47956297, 2265969327, 2865804126, 1364027301, 2267528752,
    1998395705, 576397983, 636085149, 3876141063, 1131266725, 3949079092,
    1674557074, 2566739348, 3782985982, 2164386649, 550438955, 2491039847,
    2409394861, 3757073140, 3509849961, 3972853470, 1377009785, 2164834118,
    820549672, 2867309379, 1454756115, 94270429, 2974978638, 2915205038,
    1887247447, 3641720023, 4292314015, 702694146, 1808155309, 95993403,
    1529688311, 2883286160, 1410658736, 3225014055, 1903093988, 2049895643,
    476880516, 3241604078, 3709326844, 2531992854, 265580822, 2920230147,
    4294230868, 408106067, 3683123785, 1782150222, 3876124798, 3400886112,
    1837386661, 664033147, 3948403539, 3572529266, 4084780068, 691101764,
    1191456665, 3559651142, 709364116, 3999544719, 189208547, 3851247656,
    69124994, 1685591380, 1312437435, 2316872331, 1466758250, 1979107610,
    2611873442, 80372344, 1251839752, 2716578101, 176193185, 2142192370,
    1179562050, 1290470544, 1957198791, 1435943450, 2989992875, 3703466909,
    1302678442, 3343948619, 3762772165, 1438266632, 1761719790, 3668101852,
    1283600006, 671544087, 1665876818, 3645433092, 3760380605, 3802664867,
    1635015896, 1060356828, 1666255066, 2953295653, 2827859377, 386702151,
    3372348076, 4248620909, 2259505262]


def ror(x,i):
    """
    Rotate right x by i locations.
    x is a dword
    """
    return ((x >> i) | (x << (WORD_BITSIZE - i))) & MAX_WORD

NUM_ITERS = 4
def perm(num,x):
    """
    A permutation from dwords to dwords.
    num is the number of permutation (This could generate many different
    permutation functions)
    x is the input dword.
    """
    for i in range(NUM_ITERS):
        x += RAND_DWORDS[(i + num + x) % len(RAND_DWORDS)]
        x &= MAX_WORD
        ror_index = (x ^ RAND_DWORDS[(i + num + 1) % len(RAND_DWORDS)]
                     ) % WORD_BITSIZE
        x = ror(x,ror_index)
        x ^= RAND_DWORDS[(i + num + x) % len(RAND_DWORDS)]
        ror_index = (x ^ RAND_DWORDS[(i + num + 1) % len(RAND_DWORDS)]
                     ) % WORD_BITSIZE
        x = ror(x,ror_index)
        assert (x <= MAX_WORD) and (x >= 0)
    return x


def bytes_to_num(data):
    """
    Convert a string to a number
    """
    return int.from_bytes(bytes=data,byteorder='big')

def slow_sign(data,num_perms):
    """
    Sign over data.
    Use num_perms permutations. (The more you have, the more sensitive is the
    comparison later).
    """
    nbytes = WORD_BYTESIZE
    if len(data) < nbytes:
        raise Catalog1Error(f'data must be at least of size {nbytes} bytes.')

    res_sign = []

    for p in range(num_perms):
        num_iters = len(data) - nbytes + 1
        cur_sign = min([perm(p,bytes_to_num(data[i:i+nbytes])) for i in 
                        range(num_iters)])
        res_sign.append(cur_sign)

    return res_sign

# --- Numba JIT Accelerated Implementation ---

@njit(inline='always')
def _ror_jit(val, r, mask, word_bits):
    r &= word_bits - 1
    return ((val >> r) | ((val << (word_bits - r)) & mask)) & mask

@njit(inline='always')
def _perm_jit(p, x, rd, rlen, mask, word_bits):
    for i in range(4): # NUM_ITERS
        # Explicitly cast to int64 to avoid float64 inference from %
        idx = int((i + p + x) % rlen)
        x = (x + rd[idx]) & mask
        r = int((x ^ rd[int((i + p + 1) % rlen)]) % word_bits)
        x = _ror_jit(x, r, mask, word_bits)
        x ^= rd[int((i + p + x) % rlen)]
        r = int((x ^ rd[int((i + p + 1) % rlen)]) % word_bits)
        x = _ror_jit(x, r, mask, word_bits)
    return x & mask

@njit(parallel=True)
def _numba_sign_kernel(data, num_perms, rd_array):
    """
    Core JIT kernel. 
    Parallelizes across permutations (num_perms).
    """
    n = len(data)
    rlen = len(rd_array)
    mask = np.uint32(0xFFFFFFFF)
    word_bits = 32
    
    mins = np.full(num_perms, 0xFFFFFFFF, dtype=np.uint32)
    
    # Parallelize over permutations (the 16 slots)
    for p in prange(num_perms):
        current_min = np.uint32(0xFFFFFFFF)
        
        # Sliding window logic
        # Seed first window
        if n >= 4:
            x = (np.uint32(data[0]) << 24) | (np.uint32(data[1]) << 16) | (np.uint32(data[2]) << 8) | np.uint32(data[3])
            v = _perm_jit(p, x, rd_array, rlen, mask, word_bits)
            if v < current_min:
                current_min = v
                
            for i in range(n - 4):
                # Roll window
                x = ((x << 8) & mask) | np.uint32(data[i+4])
                v = _perm_jit(p, x, rd_array, rlen, mask, word_bits)
                if v < current_min:
                    current_min = v
                    
        mins[p] = current_min
        
    return mins

def numba_sign(data: bytes, num_perms: int) -> list[int]:
    """Numba-powered signature calculation (Native Speed)."""
    rd_array = np.array(RAND_DWORDS, dtype=np.uint32)
    data_array = np.frombuffer(data, dtype=np.uint8)
    res = _numba_sign_kernel(data_array, num_perms, rd_array)
    return [int(x) for x in res]

# --- End Numba JIT ---

#endregion -- Original Implementation from FCatalog --


#region -- Optimised Implementation --

def _pack_signature_u32_be(sig):
    # sig: iterable of ints (0..0xFFFFFFFF) -> bytes, big-endian
    return b"".join(struct.pack(">I", v & 0xFFFFFFFF) for v in sig)

def fast_sign(data: bytes, num_perms: int) -> list[int]:
    """
    Faster signature builder than slow_sign.
    - Uses a rolling 4-byte window to avoid slicing/allocations.
    - Inlines and local-binds the permutation.
    Returns: list of length num_perms with 32-bit minima.
    """
    if len(data) < WORD_BYTESIZE:
        raise Catalog1Error(f"data must be at least {WORD_BYTESIZE} bytes")

    rd = RAND_DWORDS
    rlen = len(rd)
    mask = 0xFFFFFFFF
    word_bits = WORD_BITSIZE  # 32

    def inline_ror(val: int, r: int) -> int:
        r &= word_bits - 1
        return ((val >> r) | ((val << (word_bits - r)) & mask)) & mask

    # Inline permutation
    def inline_perm(p: int, x: int) -> int:
        idx = (0 + p + x) % rlen
        x = (x + rd[idx]) & mask
        r = (x ^ rd[(0 + p + 1) % rlen]) % word_bits
        x = inline_ror(x, r)
        x ^= rd[(0 + p + x) % rlen]
        r = (x ^ rd[(0 + p + 1) % rlen]) % word_bits
        x = inline_ror(x, r)

        idx = (1 + p + x) % rlen
        x = (x + rd[idx]) & mask
        r = (x ^ rd[(1 + p + 1) % rlen]) % word_bits
        x = inline_ror(x, r)
        x ^= rd[(1 + p + x) % rlen]
        r = (x ^ rd[(1 + p + 1) % rlen]) % word_bits
        x = inline_ror(x, r)

        idx = (2 + p + x) % rlen
        x = (x + rd[idx]) & mask
        r = (x ^ rd[(2 + p + 1) % rlen]) % word_bits
        x = inline_ror(x, r)
        x ^= rd[(2 + p + x) % rlen]
        r = (x ^ rd[(2 + p + 1) % rlen]) % word_bits
        x = inline_ror(x, r)

        idx = (3 + p + x) % rlen
        x = (x + rd[idx]) & mask
        r = (x ^ rd[(3 + p + 1) % rlen]) % word_bits
        x = inline_ror(x, r)
        x ^= rd[(3 + p + x) % rlen]
        r = (x ^ rd[(3 + p + 1) % rlen]) % word_bits
        x = inline_ror(x, r)

        return x & mask

    # Initialize minima
    mins = [0xFFFFFFFF] * num_perms

    mv = memoryview(data)
    n = len(data)
    num_iters = n - 3

    # Seed first 4-byte window
    x = (mv[0] << 24) | (mv[1] << 16) | (mv[2] << 8) | mv[3]

    for i in range(num_iters):
        xi = x  # Local bind
        # Update minima for all permutations
        for p in range(num_perms):
            v = inline_perm(p, xi)
            if v < mins[p]:
                mins[p] = v

        # Roll window: add next byte (if any)
        if i + 4 < n:
            x = ((x << 8) & mask) | mv[i + 4]

    return mins

#endregion -- Optimised Implementation --

#endregion PRIMITIVES

#region CATALOG1
class Catalog1:
    
    __slots__ = ("digest",)
    
    def __init__(self, digest: HexValue):
        self.digest = HexStr(digest)
        if self.byte_size % WORD_BYTESIZE != 0:
            raise Catalog1Error(
                f"Digest length must be a multiple of {WORD_BYTESIZE}")

    def __repr__(self) -> str:
        return f"Catalog1(digest={self.digest})"
    
    def __str__(self) -> str:
        return str(self.digest)
    
    def __bytes__(self) -> bytes:
        return bytes(self.digest)

    @staticmethod
    def _signature_to_bytes(sig) -> bytes:
        return b"".join(struct.pack(">I", x & 0xFFFFFFFF) for x in sig)
    
    @staticmethod
    def npermutations_from_size(byte_size: int) -> int:
        """
        Given a byte size, returns the number of permutations required to 
        generate a Catalog1 digest of that size.
        """
        return byte_size // WORD_BYTESIZE
    
    @property
    def byte_size(self) -> int:
        return len(self.digest) // 2
    
    @property
    def npermutations(self) -> int:
        return self.npermutations_from_size(self.byte_size)

    @classmethod
    def compute_digest(cls, blob: bytes, byte_size: int, 
                       use_fast_sign=True) -> HexStr:
        """
        Computes a Catalog1 digest from any blob of bytes.
        Args:
            blob (bytes): The blob of bytes to compute the digest from.
            byte_size (int): The byte size of the resulting digest.
            use_fast_sign (bool): Whether to use the fast sign algorithm which 
                avoids loops and allocations. If False, the original slow sign 
                algorithm is used (as provided in the FCatalog website).
        Returns:
            HexStr: The Catalog1 digest in hexadecimal string format.
        Raises:
            Catalog1Error: If the blob is less than the word's size (4 bytes).
        """
        nperms = cls.npermutations_from_size(byte_size)
        if use_fast_sign:
            if HAS_NUMBA:
                signature = numba_sign(blob, nperms)
            else:
                signature = fast_sign(blob, nperms)
        else:
            signature = slow_sign(blob, nperms)

        packed_signature = _pack_signature_u32_be(signature)
        return HexStr.from_bytes(packed_signature)
    
    @classmethod
    def hash_similarity(cls, hash1: HexValue, hash2: HexValue, 
                        precision: Optional[int] = None) -> float:
        hash1 = hexvalue_to_bytes(hash1)
        hash2 = hexvalue_to_bytes(hash2)
        if len(hash1) != len(hash2):
            raise Catalog1Error("Hash sizes must match")
        
        dtype = f">u{WORD_BYTESIZE}"
        array1 = np.frombuffer(hash1, dtype=dtype)
        array2 = np.frombuffer(hash2, dtype=dtype)
        matches = (array1 == array2).sum()
        sim = matches / array1.size
        return sim if precision is None else round(sim, ndigits=precision)
    
    @classmethod
    def from_hexvalue(cls, input_data: HexValue, byte_size=64, 
                        use_fast_sign=True) -> Self:
        """
        Creates a Catalog1 instance from any value amongst the following types:
        - a hex string (e.g. "deadbeef")
        - an integer
        - a bytes object
        """
        data_bytes = hexvalue_to_bytes(input_data)
        digest = cls.compute_digest(data_bytes, byte_size, use_fast_sign)
        return cls(digest)
    
    @classmethod
    def from_fcode(cls, fcode_data: R2CodeInfoIn, byte_size=64, 
                   use_fast_sign=True) -> Self:
        input_data = ""
        for block_data in fcode_data["blocks"]:
            for op_data in block_data["ops"]:
                input_data += op_data["bytes"]
        return cls.from_hexvalue(input_data, byte_size, 
                                   use_fast_sign=use_fast_sign)

    def similarity(self, other: HexValue | Self) -> float:
        if isinstance(other, Catalog1):
            if other.npermutations != self.npermutations:
                raise Catalog1Error(
                    "Permutation counts must match, got "
                    f"{self.npermutations} and {other.npermutations}")
            other = bytes(other)
        else:
            other = hexvalue_to_bytes(other)
            if len(other) != self.byte_size * 2:
                raise Catalog1Error(
                    f"Digest hex length mismatch: expected {self.byte_size*2}"
                    f" hex chars, got {len(other)}")
        
        return self.hash_similarity(bytes(self), other)
#endregion CATALOG1
