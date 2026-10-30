"""Unit and integration tests for the 4-round SPN cipher and differential cryptanalysis."""

from __future__ import annotations

import random

import pytest

from modules import Bits, DifferentialAttack, EncryptionOracle, spn


def test_bits_validation_and_operations() -> None:
    Bits.check_bits("1001", expected_length=4)
    with pytest.raises(ValueError):
        Bits.check_bits("100a")
    with pytest.raises(ValueError):
        Bits.check_bits("01110", expected_length=4)

    a = Bits("10101")
    b = Bits("01100")
    assert str(a ^ b) == "11001"
    assert str(a | b) == "11101"
    assert str(a & b) == "00100"
    assert str(Bits("000101", do_trim=True)) == "101"
    assert Bits("1010").to_int() == 10
    assert Bits.from_hexstring("0f").to_hexstring() == "0f"
    assert Bits.from_text("OK").to_py_bytes() == b"OK"


def test_sbox_and_pbox_invertibility() -> None:
    for val in range(16):
        nibble = Bits(f"{val:04b}", do_trim=False)
        assert spn.inverse_s_box(spn.s_box(nibble)).bit_list == nibble.bit_list

    block = Bits("0101010001001010", do_trim=False)
    permuted = spn.p_box(block, spn.heys_p_matrix)
    assert spn.inverse_p_box(permuted, spn.heys_p_matrix).bit_list == block.bit_list
    assert permuted.to_int() == spn.permute_16bit_int(block.to_int())


def test_spn_full_encryption_decryption_roundtrip() -> None:
    plaintext = Bits("0101010001001010", do_trim=False)
    master_key = Bits(
        "00010100000101001111001101011111001000010111101110001000111110101001001001101010",
        do_trim=False,
    )
    ciphertext = spn.spn(plaintext, master_key, spn.heys_p_matrix)
    recovered = spn.inverse_spn(ciphertext, master_key, spn.heys_p_matrix)
    assert recovered.bit_list == plaintext.bit_list


def test_ddt_and_3_round_differential_trails() -> None:
    attack = DifferentialAttack(expected_right_pairs=12)
    # Heys S-box differential 0xB -> 0x2 has propagation count 8/16
    assert attack.ddt[0x0B][0x02] == 8
    # Each row of the 16x16 DDT must sum to 16
    assert all(sum(row) == 16 for row in attack.ddt)

    trails = attack.get_highly_probable_trails(round_num=3)
    assert len(trails) > 0
    best_pref, best_prob, best_in, best_out = trails[0]
    assert best_prob == pytest.approx(9 / 256)
    assert best_in > 0
    assert best_out > 0
    assert best_pref == pytest.approx(best_prob)


def test_complete_80bit_master_key_recovery() -> None:
    random.seed(42)
    fixed_key = (
        "0011101010010100"
        "1101011000111111"
        "0100101111100010"
        "1010010110010110"
        "0110110011110011"
    )
    oracle = EncryptionOracle(secret_key_bits=fixed_key)
    attack = DifferentialAttack(expected_right_pairs=24)

    extracted_keys = attack.execute_complete_break(oracle.encrypt, descriptive=False)
    assert oracle.is_complete_break_successful(extracted_keys)
    assert all(entry["is_correct"] for entry in oracle.verify_keys(extracted_keys))
