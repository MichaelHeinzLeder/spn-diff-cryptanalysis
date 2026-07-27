class Bits:
    """
    A class representing a list of bits.

    Attributes:
        bit_list: list of integer (bits)
    """

    @staticmethod
    def check_bits(bitstring: str, expected_length: int = 0) -> None:
        """
        Check for valid bitstring of length n if n > 0.

        Parameters:
            bitstring: string of n bits
            expected_length: expected bitstring length

        Raises:
            ValueError: If bitstring has invalid characters or wrong length.
        """
        if 0 < expected_length != len(bitstring):
            raise ValueError(f'Input bitstring must be of expected length {expected_length}')
        if not all(c in '01' for c in bitstring):
            raise ValueError("Input must be a string containing only '0' and '1'")

    def __init__(self, bits_value: str | list[int], do_trim: bool=False) -> None:
        """
        Initialize a Bits object.

        Parameters:
            bits_value: String of bits or list of bits.
            do_trim: Remove leading zeros.
        """
        self.bit_list = []

        if isinstance(bits_value, str):
            Bits.check_bits(bits_value)
            for bit in bits_value:
                self.bit_list.append(int(bit))

        elif isinstance(bits_value, list):
            for b in bits_value:
                if b not in (0, 1):
                    raise ValueError(f'All list elements must be 0 or 1, got {b!r}')
            self.bit_list = bits_value

        else:
            raise TypeError('Bits must be created from a string or a list')

        if do_trim:
            self.trim()

    def __str__(self) -> str:
        """
        Returns the bits stored in this Bits object as a string.
        
        Returns:
            String of bits.
        """
        return ''.join(str(bit) for bit in self.bit_list)
    
    def __len__(self) -> int:
        """
        Returns the amount of bits in this object.
        
        Returns:
            bit_list length.
        """
        return len(self.bit_list)

    def trim(self) -> 'Bits':
        """
        Removes leading zeroes.

        Returns:
            Trimmed Bits object.
        """
        for i, x in enumerate(self.bit_list):
            if x == 1:
                return Bits(self.bit_list[i:])
        return Bits([0])

    def get_bits_as_byte_array(self, do_trim: bool = False) -> list[str]:
        """
        Returns the bits stored in this Bits object as list of strings grouped as bytes.
        ['01011010', ...]

        Parameters:
            do_trim: Remove leading zeros.

        Returns:
            List of byte strings in bit representation.
        """
        if do_trim:
            self.trim()

        # calculate missing bits to a multiple of 8
        missing_bits = (-len(self.bit_list)) % 8

        # insert 0s at the front to get to a list size multiple of 8
        temp_bits = [0 for _ in range(missing_bits)] + self.bit_list

        byte_array = []

        # fill list with bytes
        for i in range(0, len(temp_bits), 8):
            byte_array.append(''.join(str(bit) for bit in temp_bits[i:i+8]))

        return byte_array

    def __add__(self, other: 'Bits') -> 'Bits':
        """
        Append Bits object.

        Parameters:
            other: Bits object to append.

        Returns:
            Bits object

        Examples:
        >>> result = Bits('101') + Bits('010')
        >>> print(result)
        101010
        """
        return Bits(self.bit_list + other.bit_list)

    def __xor__(self, other: 'Bits', do_trim: bool = False) -> 'Bits':
        """
        Performs a bitwise XOR operation with another Bits object and returns a new Bits object.

        Parameters:
            other: Bits object
            do_trim: Remove leading zeros.

        Returns:
            Bits object

        Examples:
        >>> result = Bits('10101') ^ Bits('01100')
        >>> print(result)
        11001
        """
        l1 = other.bit_list[:]
        l2 = self.bit_list[:]

        # bring both bit lists to same size
        max_len = max(len(l1), len(l2))
        l1 = [0] * (max_len - len(l1)) + l1
        l2 = [0] * (max_len - len(l2)) + l2

        result = Bits([int(bit1) ^ int(bit2) for bit1, bit2 in zip(l1, l2)])

        if do_trim:
            result = result.trim()

        return result

    def __or__(self, other: 'Bits', do_trim: bool) -> 'Bits':
        """
        Performs a bitwise OR operation with another Bit object and returns a new Bits object.

        Parameters:
            other: Bits object
            do_trim: Remove leading zeros.

        Returns:
            Bits object

        Examples:
        >>> result = Bits('1011', do_trim=True) | Bits('0010', False)
        >>> print(result)
        1011
        """
        l1 = other.bit_list[:]
        l2 = self.bit_list[:]

        # bring both bit lists to same size
        max_len = max(len(l1), len(l2))
        l1 = [0] * (max_len - len(l1)) + l1
        l2 = [0] * (max_len - len(l2)) + l2

        result = Bits([bit1 | bit2 for bit1, bit2 in zip(l1, l2)])

        if do_trim:
            result = result.trim()

        return result

    def __lshift__(self, positions: int, fill_bit: int = 0) -> 'Bits':
        """
        Logical left shift operation.

        Parameters:
            positions: amount of positions to shift
            fill_bit: bit used to fill on the right

        Returns:
            Bits object

        Examples:
        >>> result = Bits('101') << 3
        >>> print(result)
        101000
        """
        if positions < 0:
            raise ValueError('positions must be non-negative')

        if fill_bit not in (0, 1):
            raise ValueError('Expected fill_bit needs to be an integer bit (0 or 1)')

        bits = self.bit_list[:]
        bits.extend([fill_bit] * positions)
        return Bits(bits)

    def __rshift__(self, amount: int) -> 'Bits':
        """
        Logical right shift operation.

        Parameters:
            amount: The amount of bits to remove from the right.

        Returns:
            Bits object

        Examples:
        >>> result = Bits('101111') >> 3
        >>> print(result)
        101
        """
        if amount < 0:
            raise ValueError('amount must be non-negative')

        amount = min(amount, len(self.bit_list))

        new_len = len(self.bit_list) - amount

        return Bits(self.bit_list[:new_len])
    
    def __eq__(self, other: 'Bits') -> bool:
        """
        Checks if the two Bits objects represent the same Bit value ignoring leading zeroes.

        Parameters:
            other: The Bits object to compare with.

        Returns:
            Boolean if equal (True) or not (False).
        """
        if not isinstance(other, Bits):
            return NotImplemented

        thisCopy = self.trim()
        otherCopy = other.trim()

        return thisCopy.bit_list == otherCopy.bit_list

    def to_int(self) -> int:
        """
        Converts the bits stored in this Bits object to an integer.

        Returns:
        Integer representation of the bits.

        Examples:
        >>> result = Bits('1010').to_int()
        >>> print(result)
        10
        """
        return int(str(self), 2)

    def get_nibble(self, idx: int) -> int:
        """
        Extracts a specific 4-bit block (nibble) from the bit string.

        Parameters:
        idx: The index of the nibble (0-indexed, where 0 is the least significant / rightmost nibble).

        Returns:
        Integer value (0-15) of the extracted nibble.
        """
        val = self.to_int()
        return (val >> (idx << 2)) & 0xf

    def set_nibble(self, idx: int, nibble_val: int) -> 'Bits':
        """
        Overwrites a specific 4-bit block (nibble) and returns a new Bits object
        maintaining the original bit length.

        Parameters:
        idx: The index of the nibble to replace (0-indexed, from the right).
        nibble_val: The new integer value (0-15) to insert.

        Returns:
        Bits object
        """
        val = self.to_int()
        bit_mask = ~(0xf << (idx << 2))
        new_val = (val & bit_mask) | (nibble_val << (idx << 2))

        return Bits(f"{new_val:0{len(self.bit_list)}b}")
    
    def to_hexstring(self) -> str:
        """
        Convert the bits in this object to a hex string

        Returns:
            hex bit string
        """
        hex_length = (len(str(self)) + 3) // 4

        return format(int(str(self), 2), "x").zfill(hex_length)

    @staticmethod
    def from_hexstring(hexstring: str) -> 'Bits':
        """
        Convert a hex string to an Bits object

        Parameters:
            hexstring: string of hex values

        Raises:
            ValueError: If hexstring has invalid characters.

        Returns:
            Bits object
        """
        try:
            bitstring = bin(int(hexstring, 16))[2:]

            leading_zeroes = len(hexstring) * 4 - len(bitstring)
            
            bitstring = bitstring.zfill(leading_zeroes + len(bitstring))

            return Bits(bitstring)
        except ValueError:
            raise ValueError("Input must be a string containing only '0', ..., '9', 'a', ..., 'f'")
    
    @staticmethod
    def from_text(text: str) -> 'Bits':
        """
        Convert a text corresponding to ascii

        Parameters:
            text: text, which will be converted

        Returns:
            Bits object
        """
        ascii_bytes = text.encode("ascii")
        
        return Bits("".join(format(byte, "08b") for byte in ascii_bytes))

    def to_py_bytes(self) -> bytes:
        """
        Convert bits to a b'\x00\x01' style bytes object

        Returns:
            bytes object
        """
        result = bytearray()

        for byte_string in self.get_bits_as_byte_array():
            result.append(int(byte_string, 2))

        return bytes(result)
    
    @staticmethod
    def from_py_bytes(bytes: bytes) -> 'Bits':
        """
        Convert a bytes object (b'\x00\x01') to a Bits object

        Parameters:
            bytes: bytes object, which will be converted

        Returns:
            Bits object
        """
        return Bits("".join(f"{byte:08b}" for byte in bytes))