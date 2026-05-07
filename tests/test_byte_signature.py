import pytest
from binrankbench.modules.byte_signature import ByteSignature, compare_signatures

# Note: These tests assume your `hexvalue_to_bytes` function correctly
# converts hex strings like "1234" to b'\x12\x34'.

# IMPORTANT: ByteSignature.compare (and compare_signatures) enforces a minimum
# cyclomatic complexity (min_cc=10 by default). Signatures constructed with the
# default cc=0 will always score 0.0. Tests that verify non-zero similarity
# must pass cc >= 10 when constructing ByteSignature objects.

CC_ENOUGH = 10  # Minimum cc value to pass the similarity guard


class TestByteSignature:
    def test_creation_and_masking_str(self):
        # Test full match (FFFF -> prints hex) and zero mask (FF00 -> prints ..)
        sig = ByteSignature("1234", "FF00")
        assert str(sig) == "12.."

        # Test partial bitmask (Radare2 format)
        # Bytes: 0x12, 0x34. Mask: 0xF0, 0xFF
        # Mask applied: (0x12 & 0xF0) = 0x10. (0x34 & 0xFF) = 0x34.
        # String representation of first byte should show the bitwise syntax.
        sig_partial = ByteSignature("1234", "F0FF")
        assert str(sig_partial) == "[10&f0]34"

    def test_cap_byte_size(self):
        # Default cap is 500 bytes. We'll test with a 2-byte cap here.
        sig = ByteSignature("123456", "FFFFFF", cap_byte_size=2)
        assert sig.length == 2
        assert str(sig) == "1234"

        # Test truncation on identical strings — cc must be >= min_cc for
        # compare_signatures to return a non-zero score.
        s1 = ByteSignature("112233", "FFFFFF", cap_byte_size=2, cc=CC_ENOUGH)
        s2 = ByteSignature("1122", "FFFF", cc=CC_ENOUGH)
        # 2 fully matching bytes, max_len=2.
        # Matching bits = 16, total_intersect_bits = 16.
        # density = (16/8) / 2 = 1.0. min_size check: 16 bits == 2 bytes < 16 bytes → 0.0
        # CHANGED: min_size default is 16 bytes (128 bits). Two bytes fail the entropy
        # guard so the score is 0.0. Use a small dedicated helper to bypass the guard.
        raw = ByteSignature.compare(s1, s2, min_size=0, min_cc=CC_ENOUGH)
        assert raw == 1.0

    def test_compare_identical(self):
        # min_size=0 bypasses entropy guard; min_cc=CC_ENOUGH bypasses cc guard.
        s1 = ByteSignature("1234", "FFFF", cc=CC_ENOUGH)
        s2 = ByteSignature("1234", "FFFF", cc=CC_ENOUGH)
        assert ByteSignature.compare(s1, s2, min_size=0, min_cc=CC_ENOUGH) == 1.0

    def test_compare_different(self):
        s1 = ByteSignature("1234", "FFFF", cc=CC_ENOUGH)
        s2 = ByteSignature("5678", "FFFF", cc=CC_ENOUGH)
        assert ByteSignature.compare(s1, s2, min_size=0, min_cc=CC_ENOUGH) == 0.0

    def test_compare_partial(self):
        # 1234 vs 1278 -> match on 1st byte, fail on 2nd.
        # Matching bits: byte0 0x12==0x12 (8 bits), byte1 0x34!=0x78 (0 bits)
        # total_intersect_bits = 16 (both masks 0xFF)
        # density = (8/8) / 2 = 0.5
        s1 = ByteSignature("1234", "FFFF", cc=CC_ENOUGH)
        s2 = ByteSignature("1278", "FFFF", cc=CC_ENOUGH)
        assert ByteSignature.compare(s1, s2, min_size=0, min_cc=CC_ENOUGH) == 0.5

        # 1234 (mask FF00 -> 12..) vs 1278 (mask FFFF -> 1278)
        # Byte 0: 12 vs 12, common_mask=0xFF → 8 matching bits
        # Byte 1: common_mask = 0x00 & 0xFF = 0x00 → skipped (continue)
        # matching_bits=8, total_intersect_bits=8
        # density = (8/8) / 2 = 0.5
        s3 = ByteSignature("1234", "FF00", cc=CC_ENOUGH)
        s4 = ByteSignature("1278", "FFFF", cc=CC_ENOUGH)
        assert ByteSignature.compare(s3, s4, min_size=0, min_cc=CC_ENOUGH) == 0.5

    def test_compare_different_lengths(self):
        # CHANGED: The implementation normalises by max(len, len) — density mode.
        # Lengths are 2 and 1. max_len = 2.
        # Byte 0: 0x12 == 0x12, mask 0xFF: 8 matching bits / 8 intersect bits.
        # Byte 1: missing in sig2, loop ends (zip stops at min length).
        # matching_bits=8, density = (8/8) / 2 = 0.5
        s1 = ByteSignature("1234", "FFFF", cc=CC_ENOUGH)
        s2 = ByteSignature("12", "FF", cc=CC_ENOUGH)

        assert ByteSignature.compare(s1, s2, min_size=0, min_cc=CC_ENOUGH) == 0.5

    def test_compare_empty_raises_error(self):
        # CHANGED: The new init strictly guards against empty values to prevent
        # divide-by-zero or alignment errors later on.
        with pytest.raises(ValueError):
            ByteSignature("", "")

        with pytest.raises(ValueError):
            ByteSignature("1234", "")

    def test_mismatched_lengths_raises_error(self):
        # Ensures that a 2-byte value must have a 2-byte mask
        with pytest.raises(ValueError):
            ByteSignature("1234", "FF")

    def test_radare2_specific_examples(self):
        # Recreating the scenarios we discussed to validate the R2 similarity logic.
        # All signatures use cc=CC_ENOUGH and min_size=0 to isolate length/mask
        # behaviour from the entropy and cc guards.

        # Example A: `12..56` (120056 / FF00FF) vs `1234` (1234 / FFFF)
        # max_len = 3 (sig A is longer).
        # B0: common_mask=0xFF, 0x12==0x12 → 8 bits
        # B1: common_mask=0xFF & 0x00 = 0 → skipped (continue)
        # B2: missing in sigA2 (zip stops at min_len=2) → 0 bits
        # matching_bits=8, density = (8/8) / 3 = 0.333...
        sA1 = ByteSignature("120056", "FF00FF", cc=CC_ENOUGH)
        sA2 = ByteSignature("1234", "FFFF", cc=CC_ENOUGH)
        assert round(ByteSignature.compare(sA1, sA2, min_size=0, min_cc=CC_ENOUGH), 2) == 0.33

        # Example B: `12..56` (120056 / FF00FF) vs `12..` (1200 / FF00)
        # max_len = 3.
        # B0: common_mask=0xFF, 0x12==0x12 → 8 bits
        # B1: common_mask=0x00 & 0x00 = 0 → skipped
        # B2: missing in sigB2 → 0 bits
        # density = (8/8) / 3 = 0.333...
        sB1 = ByteSignature("120056", "FF00FF", cc=CC_ENOUGH)
        sB2 = ByteSignature("1200", "FF00", cc=CC_ENOUGH)
        assert round(ByteSignature.compare(sB1, sB2, min_size=0, min_cc=CC_ENOUGH), 2) == 0.33

        # Example C: `12..56` (120056 / FF00FF) vs `..56` (0056 / 00FF)
        # max_len = 3.
        # B0: common_mask=0xFF & 0x00 = 0 → skipped
        # B1: common_mask=0x00 & 0xFF = 0 → skipped
        # B2: missing in sigC2 → 0 bits
        # matching_bits=0, density = 0.0
        sC1 = ByteSignature("120056", "FF00FF", cc=CC_ENOUGH)
        sC2 = ByteSignature("0056", "00FF", cc=CC_ENOUGH)
        assert ByteSignature.compare(sC1, sC2, min_size=0, min_cc=CC_ENOUGH) == 0.0
