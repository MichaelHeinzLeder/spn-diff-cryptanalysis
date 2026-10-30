"""Chosen-plaintext attack (CPA) encryption oracle for the 4-round SPN cipher."""

from __future__ import annotations

import secrets
from typing import TypedDict

from modules import spn
from modules.bits import Bits


class SubkeyVerificationResult(TypedDict):
    """Structured comparison between an extracted round subkey and the oracle's ground truth."""

    subkey: str
    expected_hex: str
    extracted_hex: str
    expected_bin: str
    extracted_bin: str
    is_correct: bool


class EncryptionOracle:
    """Black-box encryption oracle encapsulating an 80-bit master key for CPA evaluation."""

    def __init__(self, secret_key_bits: str | None = None) -> None:
        """Initializes the oracle with a caller-supplied or CSPRNG-generated 80-bit master key.

        Args:
            secret_key_bits: Optional 80-character binary string ('0'/'1'). If omitted,
                a uniform 80-bit key is generated via `secrets.randbits(80)`.
        """
        if secret_key_bits is not None:
            Bits.check_bits(secret_key_bits, expected_length=80)
            self.secret_key_bits = secret_key_bits
        else:
            self.secret_key_bits = f"{secrets.randbits(80):080b}"

        self._master_key_bits = Bits(self.secret_key_bits, do_trim=False)
        self._real_subkeys: list[int] = [
            int(self.secret_key_bits[i : i + 16], 2) for i in range(0, 80, 16)
        ]

    def encrypt(self, plaintext_int: int) -> int:
        """Encrypts a 16-bit plaintext integer under the hidden 80-bit master key.

        Args:
            plaintext_int: Unsigned 16-bit plaintext integer in [0, 0xFFFF].

        Returns:
            Unsigned 16-bit ciphertext integer in [0, 0xFFFF].
        """
        if not 0 <= plaintext_int <= 0xFFFF:
            raise ValueError(f"Plaintext must be a 16-bit integer, got {plaintext_int}")
        pt_bits = Bits(f"{plaintext_int:016b}", do_trim=False)
        ct_bits = spn.spn(pt_bits, self._master_key_bits, spn.heys_p_matrix)
        return ct_bits.to_int()

    def verify_keys(self, extracted_keys: list[int]) -> list[SubkeyVerificationResult]:
        """Verifies a list of 5 extracted 16-bit subkeys against the internal master key.

        Args:
            extracted_keys: Sequence of five 16-bit integers [K1, K2, K3, K4, K5].

        Returns:
            Per-round verification records without exposing the raw internal state.
        """
        if len(extracted_keys) != 5:
            raise ValueError(f"Expected 5 round subkeys, got {len(extracted_keys)}")

        return [
            {
                "subkey": f"K{idx + 1}",
                "expected_hex": f"0x{self._real_subkeys[idx]:04X}",
                "extracted_hex": f"0x{extracted_keys[idx]:04X}",
                "expected_bin": f"{self._real_subkeys[idx]:016b}",
                "extracted_bin": f"{extracted_keys[idx]:016b}",
                "is_correct": extracted_keys[idx] == self._real_subkeys[idx],
            }
            for idx in range(5)
        ]

    def is_complete_break_successful(self, extracted_keys: list[int]) -> bool:
        """Returns True if and only if all five 16-bit round subkeys match exactly."""
        return extracted_keys == self._real_subkeys
