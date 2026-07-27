from sage.all import Matrix, vector
from sage.matrix.matrix_integer_dense import Matrix_integer_dense as SageMatrix
from sage.rings.function_field.hermite_form_polynomial import identity_matrix

from modules.bits import Bits

heys_s_map: dict[str, str] = {
    '0000': '1110',
    '0001': '0100',
    '0010': '1101',
    '0011': '0001',
    '0100': '0010',
    '0101': '1111',
    '0110': '1011',
    '0111': '1000',
    '1000': '0011',
    '1001': '1010',
    '1010': '0110',
    '1011': '1100',
    '1100': '0101',
    '1101': '1001',
    '1110': '0000',
    '1111': '0111'}

heys_p_matrix: SageMatrix = Matrix([
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
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
])


def s_box(four_bits: Bits) -> Bits:
    """
    Simulates the S-Box from heys.pdf
    :param four_bits: 4-bit Bits object
    :return: substitution for the 4 bits
    """
    key = ''.join(str(b) for b in four_bits.bit_list)
    return Bits(heys_s_map[key], do_trim=False)


def inverse_s_box(four_bits: Bits) -> Bits:
    """
    Simulates the inverse of the S-Box from heys.pdf
    :param four_bits: 4-bit Bits object (S-Box output)
    :return: 4-bit Bits object (S-Box input)
    """
    val = ''.join(str(b) for b in four_bits.bit_list)
    for key in heys_s_map:
        if heys_s_map[key] == val:
            return Bits(key, do_trim=False)
    raise Exception


def p_box(sixteen_bits: Bits, permutation: SageMatrix) -> Bits:
    """
    Simulates the P-Box from heys.pdf
    :param sixteen_bits: 16-bit Bits object
    :param permutation: 16x16 permutation matrix
    :return: permutated 16-bit Bits object
    """
    input_vector = vector(sixteen_bits.bit_list)
    output_vector = permutation * input_vector
    return Bits(''.join(str(x) for x in output_vector), do_trim=False)


def inverse_p_box(sixteen_bits: Bits, permutation: SageMatrix) -> Bits:
    """
    Simulates the inverse of the P-Box from heys.pdf
    :param sixteen_bits: 16-bit Bits object
    :param permutation: 16x16 permutation matrix
    :return: un-permutated 16-bit Bits object
    """
    input_vector = vector(sixteen_bits.bit_list)
    output_vector = permutation.inverse() * input_vector
    return Bits(''.join(str(x) for x in output_vector), do_trim=False)


def _xor(first: Bits, second: Bits) -> Bits:
    """
    Xor bit lists if they are of equal length.
    :param first: Bits object
    :param second: Bits object
    :return: XOR result as 16-bit Bits
    """
    if len(first.bit_list) != len(second.bit_list):
        raise ValueError('Input bitlists must be of equal length')
    result_val = int(str(first), 2) ^ int(str(second), 2)
    return Bits(f'{result_val:016b}', do_trim=False)


def key_mixing(sixteen_bits: Bits, sixteen_bit_key: Bits) -> Bits:
    """
    Xor of a 16-bit Bits with a 16-bit key.
    :param sixteen_bits: 16-bit Bits object
    :param sixteen_bit_key: 16-bit Bits key
    :return: Bits object, xor of the two
    """
    return _xor(sixteen_bits, sixteen_bit_key)


def spn_round(sixteen_bits: Bits, sixteen_bit_key: Bits,
              permutation: SageMatrix = identity_matrix(16)) -> Bits:
    """
    Simulates one round of the SPN from heys.pdf.
    :param sixteen_bits: 16-bit Bits object
    :param sixteen_bit_key: 16-bit Bits key
    :param permutation: 16x16 permutation matrix
    :return: 16-bit Bits object
    """
    key_mixed = key_mixing(sixteen_bits, sixteen_bit_key)
    s = str(key_mixed)
    substituted = (s_box(Bits(s[0:4], do_trim=False)) + s_box(Bits(s[4:8], do_trim=False)) +
                   s_box(Bits(s[8:12], do_trim=False)) + s_box(Bits(s[12:], do_trim=False)))
    return p_box(substituted, permutation)


def inverse_spn_round(sixteen_bits: Bits, sixteen_bit_key: Bits,
                      permutation: SageMatrix = identity_matrix(16)) -> Bits:
    """
    Simulates one inverse round of the SPN from heys.pdf.
    :param sixteen_bits: 16-bit Bits object
    :param sixteen_bit_key: 16-bit Bits key
    :param permutation: 16x16 permutation matrix
    :return: 16-bit Bits object
    """
    un_permutated = inverse_p_box(sixteen_bits, permutation)
    s = str(un_permutated)
    unsubstituted = (inverse_s_box(Bits(s[0:4], do_trim=False)) +
                     inverse_s_box(Bits(s[4:8], do_trim=False)) +
                     inverse_s_box(Bits(s[8:12], do_trim=False)) +
                     inverse_s_box(Bits(s[12:], do_trim=False)))
    return key_mixing(unsubstituted, sixteen_bit_key)


def spn(sixteen_bits: Bits, eighty_bit_key: Bits, permutation: SageMatrix) -> Bits:
    """
    Simulates the SPN consisting of 4 rounds from heys.pdf.
    :param sixteen_bits: 16-bit Bits object
    :param eighty_bit_key: 80-bit Bits key
    :param permutation: 16x16 permutation matrix
    :return: 16-bit Bits object
    """
    k = str(eighty_bit_key)
    sixteen_bit_subkeys = (
        Bits(k[0:16], do_trim=False),
        Bits(k[16:32], do_trim=False),
        Bits(k[32:48], do_trim=False),
        Bits(k[48:64], do_trim=False),
        Bits(k[64:80], do_trim=False))

    sixteen_bits = spn_round(sixteen_bits, sixteen_bit_subkeys[0], permutation)
    sixteen_bits = spn_round(sixteen_bits, sixteen_bit_subkeys[1], permutation)
    sixteen_bits = spn_round(sixteen_bits, sixteen_bit_subkeys[2], permutation)
    sixteen_bits = spn_round(sixteen_bits, sixteen_bit_subkeys[3])
    sixteen_bits = key_mixing(sixteen_bits, sixteen_bit_subkeys[4])
    return sixteen_bits


def inverse_spn(sixteen_bits: Bits, eighty_bit_key: Bits, permutation: SageMatrix) -> Bits:
    """
    Simulates the inverse of the SPN consisting of four rounds from heys.pdf.
    :param sixteen_bits: 16-bit Bits object
    :param eighty_bit_key: 80-bit Bits key
    :param permutation: 16x16 permutation matrix
    :return: 16-bit Bits object
    """
    k = str(eighty_bit_key)
    sixteen_bit_subkeys = (
        Bits(k[0:16], do_trim=False),
        Bits(k[16:32], do_trim=False),
        Bits(k[32:48], do_trim=False),
        Bits(k[48:64], do_trim=False),
        Bits(k[64:80], do_trim=False))

    sixteen_bits = key_mixing(sixteen_bits, sixteen_bit_subkeys[4])
    sixteen_bits = inverse_spn_round(sixteen_bits, sixteen_bit_subkeys[3])
    sixteen_bits = inverse_spn_round(sixteen_bits, sixteen_bit_subkeys[2], permutation)
    sixteen_bits = inverse_spn_round(sixteen_bits, sixteen_bit_subkeys[1], permutation)
    sixteen_bits = inverse_spn_round(sixteen_bits, sixteen_bit_subkeys[0], permutation)
    return sixteen_bits


if __name__ == '__main__':
    # Test Bits.check_bits
    Bits.check_bits('1001')
    Bits.check_bits('1001', 4)
    try:
        Bits.check_bits('100a')
        raise Exception('Expected ValueError for invalid chars')
    except ValueError:
        pass
    try:
        Bits.check_bits('01110', 4)
        raise Exception('Expected ValueError for invalid length')
    except ValueError:
        pass
    try:
        Bits.check_bits('190', 4)
        raise Exception('Expected ValueError for invalid chars and length')
    except ValueError:
        pass

    # Test S-Box
    for i in range(16):
        test_bits = Bits(f'{i:04b}', do_trim=False)
        if not inverse_s_box(s_box(test_bits)).bit_list == test_bits.bit_list:
            raise Exception('S-Box and its inverse shuffle bits randomly')

    test_bitstring = Bits('0101010001001010', do_trim=False)

    # Test P-Box
    if not inverse_p_box(p_box(test_bitstring, heys_p_matrix), heys_p_matrix).bit_list == test_bitstring.bit_list:
        raise Exception('P-Box and its inverse shuffle bits randomly')

    short_keystring = Bits('1001110010101001', do_trim=False)

    # Test Key Mixing
    # check for x - x = 0
    if not key_mixing(test_bitstring, test_bitstring).bit_list == [0] * 16:
        raise Exception('Key Mixing shuffles bits randomly')
    # check for x + k - k = 0
    if not key_mixing(key_mixing(test_bitstring, short_keystring), short_keystring).bit_list == test_bitstring.bit_list:
        raise Exception('Key Mixing shuffles bits randomly')

    # Test SPN Round
    round1 = spn_round(test_bitstring, short_keystring)
    inverse_round1 = inverse_spn_round(round1, short_keystring)
    if not inverse_round1.bit_list == test_bitstring.bit_list:
        raise Exception('Not permutated spn_round and its inverse shuffle bits randomly')

    round2 = spn_round(test_bitstring, short_keystring, permutation=heys_p_matrix)
    inverse_round2 = inverse_spn_round(round2, short_keystring, permutation=heys_p_matrix)
    if not inverse_round2.bit_list == test_bitstring.bit_list:
        raise Exception('Permutated spn_round and its inverse shuffle bits randomly')

    # Test SPN
    spn_keystring = Bits('00010100000101001111001101011111001000010111101110001000111110101001001001101010',
                         do_trim=False)
    result = spn(test_bitstring, spn_keystring, heys_p_matrix)
    result_inv = inverse_spn(result, spn_keystring, heys_p_matrix)
    if not result_inv.bit_list == test_bitstring.bit_list:
        raise Exception('SPN and its inverse shuffle bits randomly')

    print('Tutto bene')
