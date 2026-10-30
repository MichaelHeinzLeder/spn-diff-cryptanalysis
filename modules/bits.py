"""Bit-vector abstraction supporting bitwise arithmetic, nibble extraction, and serialization."""

from __future__ import annotations

from collections.abc import Sequence


class Bits:
    """Represents a fixed or variable-width binary vector as a sequence of {0, 1} bits.

    Attributes:
        bit_list: Underlying list of integer bits (0 or 1), ordered MSB to LSB.
    """

    bit_list: list[int]

    @staticmethod
    def check_bits(bitstring: str, expected_length: int = 0) -> None:
        """Validates that a string contains only '0'/'1' characters and matches expected_length.

        Args:
            bitstring: Binary string to validate.
            expected_length: Required bit length when strictly positive (0 disables length check).

        Raises:
            ValueError: If bitstring contains non-binary characters or has an unexpected length.
        """
        if 0 < expected_length != len(bitstring):
            raise ValueError(f"Input bitstring must be of expected length {expected_length}")
        if not bitstring or any(c not in "01" for c in bitstring):
            raise ValueError("Input must be a non-empty string containing only '0' and '1'")

    def __init__(self, bits_value: str | Sequence[int], do_trim: bool = False) -> None:
        """Initializes a Bits instance from a binary string or a sequence of {0, 1} integers.

        Args:
            bits_value: Binary string (e.g. '0101') or sequence of 0/1 integers.
            do_trim: If True, strips leading zero bits (preserving a single '0' if all zero).

        Raises:
            TypeError: If bits_value is neither a str nor a sequence of integers.
            ValueError: If any element is outside {0, 1}.
        """
        if isinstance(bits_value, str):
            self.check_bits(bits_value)
            self.bit_list = [int(bit) for bit in bits_value]
        elif isinstance(bits_value, list | tuple):
            validated: list[int] = []
            for bit in bits_value:
                if bit not in (0, 1) or isinstance(bit, bool):
                    raise ValueError(f"All sequence elements must be 0 or 1, got {bit!r}")
                validated.append(int(bit))
            if not validated:
                raise ValueError("Bits sequence must not be empty")
            self.bit_list = validated
        else:
            raise TypeError("Bits must be created from a binary string or a list of 0/1 ints")

        if do_trim:
            self.bit_list = self.trim().bit_list

    def __str__(self) -> str:
        """Returns the binary string representation (MSB first)."""
        return "".join(str(bit) for bit in self.bit_list)

    def __repr__(self) -> str:
        """Returns an unambiguous developer representation."""
        return f"Bits('{self}')"

    def __len__(self) -> int:
        """Returns the bit width of this vector."""
        return len(self.bit_list)

    def trim(self) -> Bits:
        """Returns a new Bits instance with leading zero bits removed."""
        for idx, bit in enumerate(self.bit_list):
            if bit == 1:
                return Bits(self.bit_list[idx:])
        return Bits([0])

    def get_bits_as_byte_array(self, do_trim: bool = False) -> list[str]:
        """Groups the bit vector into 8-bit binary strings, zero-padded on the left.

        Args:
            do_trim: Strip leading zeros prior to byte alignment.

        Returns:
            List of 8-character binary strings.
        """
        source_bits = self.trim().bit_list if do_trim else self.bit_list
        missing_bits = (-len(source_bits)) % 8
        padded = [0] * missing_bits + source_bits
        return [
            "".join(str(bit) for bit in padded[i : i + 8])
            for i in range(0, len(padded), 8)
        ]

    def __add__(self, other: Bits) -> Bits:
        """Concatenates two Bits vectors."""
        if not isinstance(other, Bits):
            return NotImplemented
        return Bits(self.bit_list + other.bit_list)

    @staticmethod
    def _align_vectors(left: list[int], right: list[int]) -> tuple[list[int], list[int]]:
        """Left-pads the shorter bit list with zeros so both lists have equal length."""
        max_len = max(len(left), len(right))
        return (
            [0] * (max_len - len(left)) + left,
            [0] * (max_len - len(right)) + right,
        )

    def __xor__(self, other: Bits, do_trim: bool = False) -> Bits:
        """Computes the bitwise XOR with another Bits vector."""
        if not isinstance(other, Bits):
            return NotImplemented
        l1, l2 = self._align_vectors(self.bit_list, other.bit_list)
        result = Bits([b1 ^ b2 for b1, b2 in zip(l1, l2)])
        return result.trim() if do_trim else result

    def __or__(self, other: Bits, do_trim: bool = False) -> Bits:
        """Computes the bitwise OR with another Bits vector."""
        if not isinstance(other, Bits):
            return NotImplemented
        l1, l2 = self._align_vectors(self.bit_list, other.bit_list)
        result = Bits([b1 | b2 for b1, b2 in zip(l1, l2)])
        return result.trim() if do_trim else result

    def __and__(self, other: Bits, do_trim: bool = False) -> Bits:
        """Computes the bitwise AND with another Bits vector."""
        if not isinstance(other, Bits):
            return NotImplemented
        l1, l2 = self._align_vectors(self.bit_list, other.bit_list)
        result = Bits([b1 & b2 for b1, b2 in zip(l1, l2)])
        return result.trim() if do_trim else result

    def __lshift__(self, positions: int, fill_bit: int = 0) -> Bits:
        """Appends `positions` fill bits to the LSB end (logical left shift)."""
        if positions < 0:
            raise ValueError("positions must be non-negative")
        if fill_bit not in (0, 1):
            raise ValueError("fill_bit must be 0 or 1")
        return Bits(self.bit_list + [fill_bit] * positions)

    def __rshift__(self, amount: int) -> Bits:
        """Truncates `amount` bits from the LSB end (logical right shift)."""
        if amount < 0:
            raise ValueError("amount must be non-negative")
        if amount >= len(self.bit_list):
            return Bits([0])
        return Bits(self.bit_list[: len(self.bit_list) - amount])

    def __eq__(self, other: object) -> bool:
        """Compares two Bits instances by numerical value (ignoring leading zeros)."""
        if not isinstance(other, Bits):
            return NotImplemented
        return self.trim().bit_list == other.trim().bit_list

    def to_int(self) -> int:
        """Converts the bit vector into a non-negative Python integer."""
        value = 0
        for bit in self.bit_list:
            value = (value << 1) | bit
        return value

    def get_nibble(self, idx: int) -> int:
        """Extracts a 4-bit nibble by index (0 = least significant / rightmost nibble)."""
        return (self.to_int() >> (idx << 2)) & 0xF

    def set_nibble(self, idx: int, nibble_val: int) -> Bits:
        """Replaces a 4-bit nibble by index (0 = rightmost) while preserving bit width."""
        if not 0 <= nibble_val <= 0xF:
            raise ValueError(f"nibble_val must be in [0, 15], got {nibble_val}")
        bit_width = len(self.bit_list)
        shift = idx << 2
        masked = self.to_int() & ~(0xF << shift)
        updated = masked | (nibble_val << shift)
        return Bits(f"{updated:0{bit_width}b}")

    def to_hexstring(self) -> str:
        """Formats the bit vector as a zero-padded lowercase hexadecimal string."""
        hex_length = (len(self.bit_list) + 3) // 4
        return f"{self.to_int():0{hex_length}x}"

    @staticmethod
    def from_hexstring(hexstring: str) -> Bits:
        """Parses a hexadecimal string into a Bits vector preserving leading zero nibbles."""
        if not hexstring:
            raise ValueError("Hexstring must not be empty")
        try:
            value = int(hexstring, 16)
        except ValueError as exc:
            raise ValueError(
                "Input must be a valid hexadecimal string ([0-9a-fA-F])"
            ) from exc
        bit_width = len(hexstring) * 4
        return Bits(f"{value:0{bit_width}b}")

    @staticmethod
    def from_text(text: str) -> Bits:
        """Encodes an ASCII string into a Bits vector (8 bits per character)."""
        ascii_bytes = text.encode("ascii")
        return Bits.from_py_bytes(ascii_bytes)

    def to_py_bytes(self) -> bytes:
        """Serializes the bit vector into a big-endian bytes object."""
        return bytes(int(byte_str, 2) for byte_str in self.get_bits_as_byte_array())

    @staticmethod
    def from_py_bytes(raw_bytes: bytes) -> Bits:
        """Deserializes a bytes object into a Bits vector."""
        if not raw_bytes:
            raise ValueError("raw_bytes must not be empty")
        return Bits("".join(f"{byte:08b}" for byte in raw_bytes))
