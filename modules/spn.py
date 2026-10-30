"""4-round Substitution-Permutation Network (SPN) cipher implementation (Heys, 2002)."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from modules.bits import Bits

try:
    from sage.all import Matrix, identity_matrix, vector
    from sage.matrix.matrix_integer_dense import Matrix_integer_dense as SageMatrix
except ImportError:

    class _FallbackMatrix:
        """Pure-Python 0/1 matrix fallback when SageMath is not installed."""

        def __init__(self, rows: Sequence[Sequence[int]]) -> None:
            self._rows: tuple[tuple[int, ...], ...] = tuple(
                tuple(int(x) for x in row) for row in rows
            )
            self._inverse: _FallbackMatrix | None = None

        def inverse(self) -> _FallbackMatrix:
            """Returns the inverse of an orthogonal permutation matrix (its transpose)."""
            if self._inverse is None:
                n = len(self._rows)
                transposed = [
                    [self._rows[r][c] for r in range(n)] for c in range(n)
                ]
                inv = _FallbackMatrix(transposed)
                inv._inverse = self
                self._inverse = inv
            return self._inverse

        def __mul__(self, vec: Sequence[int]) -> list[int]:
            return [
                sum(r_val * v_val for r_val, v_val in zip(row, vec))
                for row in self._rows
            ]

        def __getitem__(self, idx: int) -> tuple[int, ...]:
            return self._rows[idx]

        def __len__(self) -> int:
            return len(self._rows)

        def __eq__(self, other: object) -> bool:
            if isinstance(other, _FallbackMatrix):
                return self._rows == other._rows
            return NotImplemented

    SageMatrix = _FallbackMatrix  # type: ignore[misc,assignment]

    def Matrix(rows: Sequence[Sequence[int]]) -> _FallbackMatrix:  # noqa: N802
        return _FallbackMatrix(rows)

    def vector(elements: Sequence[int]) -> list[int]:
        return list(elements)

    def identity_matrix(size: int) -> _FallbackMatrix:
        return _FallbackMatrix(
            [[1 if r == c else 0 for c in range(size)] for r in range(size)]
        )


heys_s_map: dict[str, str] = {
    "0000": "1110",
    "0001": "0100",
    "0010": "1101",
    "0011": "0001",
    "0100": "0010",
    "0101": "1111",
    "0110": "1011",
    "0111": "1000",
    "1000": "0011",
    "1001": "1010",
    "1010": "0110",
    "1011": "1100",
    "1100": "0101",
    "1101": "1001",
    "1110": "0000",
    "1111": "0111",
}

heys_inverse_s_map: dict[str, str] = {v: k for k, v in heys_s_map.items()}

heys_p_matrix: Any = Matrix([
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0],
    [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0],
    [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0],
    [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
])

_IDENTITY_16: Any = identity_matrix(16)
_HEYS_P_INVERSE: Any = heys_p_matrix.inverse()

# Precomputed bit-position mapping for Heys' 16-bit permutation (P(i) = 4*(i mod 4) + (i // 4))
_HEYS_BIT_PERM: tuple[int, ...] = (
    0, 4, 8, 12,
    1, 5, 9, 13,
    2, 6, 10, 14,
    3, 7, 11, 15,
)


def permute_16bit_int(state: int) -> int:
    """Applies Heys' 16-bit P-box permutation directly on a 16-bit integer."""
    out = 0
    for src_bit, dst_bit in enumerate(_HEYS_BIT_PERM):
        if (state >> (15 - src_bit)) & 1:
            out |= 1 << (15 - dst_bit)
    return out


def s_box(four_bits: Bits) -> Bits:
    """Applies the 4-bit non-linear S-box substitution (π_S) from Heys (2002).

    Args:
        four_bits: 4-bit input Bits vector.

    Returns:
        Substituted 4-bit Bits vector.
    """
    key = str(four_bits)
    if key not in heys_s_map:
        raise ValueError(f"Expected 4-bit input for S-box, got '{key}'")
    return Bits(heys_s_map[key], do_trim=False)


def inverse_s_box(four_bits: Bits) -> Bits:
    """Applies the inverse 4-bit S-box substitution (π_S^-1).

    Args:
        four_bits: 4-bit S-box output Bits vector.

    Returns:
        Original 4-bit S-box input Bits vector.
    """
    val = str(four_bits)
    if val not in heys_inverse_s_map:
        raise ValueError(f"Expected 4-bit input for inverse S-box, got '{val}'")
    return Bits(heys_inverse_s_map[val], do_trim=False)


def p_box(sixteen_bits: Bits, permutation: Any) -> Bits:
    """Permutes a 16-bit block via matrix-vector multiplication (π_P).

    Args:
        sixteen_bits: 16-bit input Bits vector.
        permutation: 16x16 binary permutation matrix.

    Returns:
        Permuted 16-bit Bits vector.
    """
    input_vector = vector(sixteen_bits.bit_list)
    output_vector = permutation * input_vector
    return Bits([int(x) for x in output_vector], do_trim=False)


def inverse_p_box(sixteen_bits: Bits, permutation: Any) -> Bits:
    """Applies the inverse 16-bit permutation (π_P^-1).

    Args:
        sixteen_bits: 16-bit input Bits vector.
        permutation: 16x16 binary permutation matrix.

    Returns:
        Unpermuted 16-bit Bits vector.
    """
    inv_matrix = (
        _HEYS_P_INVERSE
        if permutation is heys_p_matrix
        else permutation.inverse()
    )
    input_vector = vector(sixteen_bits.bit_list)
    output_vector = inv_matrix * input_vector
    return Bits([int(x) for x in output_vector], do_trim=False)


def _xor(first: Bits, second: Bits) -> Bits:
    """Computes fixed-width 16-bit XOR of two equal-length Bits vectors."""
    if len(first) != len(second):
        raise ValueError("Input bit vectors must be of equal length")
    result_val = first.to_int() ^ second.to_int()
    return Bits(f"{result_val:0{len(first)}b}", do_trim=False)


def key_mixing(sixteen_bits: Bits, sixteen_bit_key: Bits) -> Bits:
    """Mixes a 16-bit state block with a 16-bit round subkey via bitwise XOR."""
    return _xor(sixteen_bits, sixteen_bit_key)


def spn_round(
    sixteen_bits: Bits,
    sixteen_bit_key: Bits,
    permutation: Any | None = None,
) -> Bits:
    """Executes one forward SPN round: key mixing, 4 parallel S-boxes, and P-box.

    Args:
        sixteen_bits: 16-bit round input block.
        sixteen_bit_key: 16-bit round subkey.
        permutation: 16x16 permutation matrix (defaults to 16x16 identity for final round).

    Returns:
        16-bit round output block.
    """
    perm = _IDENTITY_16 if permutation is None else permutation
    key_mixed = str(key_mixing(sixteen_bits, sixteen_bit_key))
    substituted = (
        s_box(Bits(key_mixed[0:4], do_trim=False))
        + s_box(Bits(key_mixed[4:8], do_trim=False))
        + s_box(Bits(key_mixed[8:12], do_trim=False))
        + s_box(Bits(key_mixed[12:16], do_trim=False))
    )
    return p_box(substituted, perm)


def inverse_spn_round(
    sixteen_bits: Bits,
    sixteen_bit_key: Bits,
    permutation: Any | None = None,
) -> Bits:
    """Executes one inverse SPN round: inverse P-box, 4 inverse S-boxes, and key mixing."""
    perm = _IDENTITY_16 if permutation is None else permutation
    unpermuted = str(inverse_p_box(sixteen_bits, perm))
    unsubstituted = (
        inverse_s_box(Bits(unpermuted[0:4], do_trim=False))
        + inverse_s_box(Bits(unpermuted[4:8], do_trim=False))
        + inverse_s_box(Bits(unpermuted[8:12], do_trim=False))
        + inverse_s_box(Bits(unpermuted[12:16], do_trim=False))
    )
    return key_mixing(unsubstituted, sixteen_bit_key)


def _split_master_key(eighty_bit_key: Bits) -> tuple[Bits, Bits, Bits, Bits, Bits]:
    """Splits an 80-bit master key into five 16-bit round subkeys (K1..K5)."""
    key_str = str(eighty_bit_key)
    if len(key_str) != 80:
        raise ValueError(f"Expected 80-bit master key, got {len(key_str)} bits")
    return (
        Bits(key_str[0:16], do_trim=False),
        Bits(key_str[16:32], do_trim=False),
        Bits(key_str[32:48], do_trim=False),
        Bits(key_str[48:64], do_trim=False),
        Bits(key_str[64:80], do_trim=False),
    )


def spn(sixteen_bits: Bits, eighty_bit_key: Bits, permutation: Any) -> Bits:
    """Encrypts a 16-bit plaintext block through the 4-round SPN cipher."""
    subkeys = _split_master_key(eighty_bit_key)
    state = spn_round(sixteen_bits, subkeys[0], permutation)
    state = spn_round(state, subkeys[1], permutation)
    state = spn_round(state, subkeys[2], permutation)
    state = spn_round(state, subkeys[3])
    return key_mixing(state, subkeys[4])


def inverse_spn(sixteen_bits: Bits, eighty_bit_key: Bits, permutation: Any) -> Bits:
    """Decrypts a 16-bit ciphertext block through the 4-round inverse SPN cipher."""
    subkeys = _split_master_key(eighty_bit_key)
    state = key_mixing(sixteen_bits, subkeys[4])
    state = inverse_spn_round(state, subkeys[3])
    state = inverse_spn_round(state, subkeys[2], permutation)
    state = inverse_spn_round(state, subkeys[1], permutation)
    return inverse_spn_round(state, subkeys[0], permutation)
