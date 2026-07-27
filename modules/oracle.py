import random
from modules import spn
from modules.bits import Bits

class EncryptionOracle:
    def __init__(self, secret_key_bits: str = None):
        """Initialisiert das Orakel mit einem festen oder random 80-Bit Key."""
        self.secret_key_bits = secret_key_bits or f"{random.getrandbits(80):080b}"

    def encrypt(self, plaintext_int: int) -> int:
        """Verschlüsselt einen 16-Bit Integer plaintext."""
        pt_bits = Bits(f"{plaintext_int:016b}")
        ct_bits = spn.spn(pt_bits, Bits(self.secret_key_bits), spn.heys_p_matrix)
        return ct_bits.to_int()

    def verify_keys(self, extracted_keys: list[int]) -> list[dict]:
        """Verifiziert extrahierte Schlüssel gegen das interne Geheimnis ohne es zurückzugeben."""
        real_keys = [int(self.secret_key_bits[i:i + 16], 2) for i in range(0, 80, 16)]

        verification_results = []
        for i in range(5):
            verification_results.append({
                "subkey": f"K{i + 1}",
                "expected_hex": f"0x{real_keys[i]:04X}",
                "extracted_hex": f"0x{extracted_keys[i]:04X}",
                "expected_bin": f"{real_keys[i]:016b}",
                "extracted_bin": f"{extracted_keys[i]:016b}",
                "is_correct": extracted_keys[i] == real_keys[i]
            })
        return verification_results

    def is_complete_break_successful(self, extracted_keys: list[int]) -> bool:
        """Gibt True zurück, wenn alle Schlüssel exakt übereinstimmen."""
        real_keys = [int(self.secret_key_bits[i:i + 16], 2) for i in range(0, 80, 16)]
        return extracted_keys == real_keys
