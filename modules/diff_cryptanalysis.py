from modules.bits import Bits
from modules import spn
from datetime import datetime
import random
import itertools


class DifferentialAttack:
    """
    Executes a complete differential cryptanalysis attack on a R-round Substitution-Permutation Network (SPN).
    """

    def __init__(self, expected_right_pairs: int = 4, num_rounds=4):
        """
        Initializes the differential attack state and computes lookup tables with a default count of 4 expected right pairs.

        Args:
            expected_right_pairs (int): adjustabel constant 'c' for the expected right pairs - meant as a measure for statistical noise.
            Determines roughly expected value N, where N ≈ c / p
            'N':= num of plaintext pairs.
            'c':= see above
            'p':= trail probability for the R-1 round differential characteristic.
            num_rounds (int): number of rounds in SPN
        """
        self.expected_right_pairs = expected_right_pairs
        self.num_rounds = num_rounds
        self.sbox_list = self._convert_sbox_to_arr(spn.heys_s_map)
        self.inverse_sbox_list = self._invert_sbox(self.sbox_list)
        self.ddt = self._build_ddt()

    @staticmethod
    def _convert_sbox_to_arr(sbox_map: dict[str, str]) -> list[int]:
        """
        Converts the string-based S-box mapping into a onedimensional int-array.

        Args:
            sbox_map (dict[str, str]): Dictionary mapping 4-bit binary strings to 4-bit binary strings.

        Returns:
            list[int]: 16-element list representing the S-box substitution.
        """
        sbox = [0] * 16
        for in_bits, out_bits in sbox_map.items():
            sbox[int(in_bits, 2)] = int(out_bits, 2)
        return sbox

    @staticmethod
    def _invert_sbox(sbox_list: list[int]) -> list[int]:
        """
        Computes the inverse S-box mapping for partial decryption.

        Args:
            sbox_list (list[int]): 16-element list representing the S-box.

        Returns:
            list[int]: 16-element list representing the inverse S-box.
        """
        inverse_sbox = [0] * 16
        for idx, val in enumerate(sbox_list):
            inverse_sbox[val] = idx
        return inverse_sbox

    def _build_ddt(self) -> list[list[int]]:
        """
        Constructs the 16x16 Difference Distribution Table (DDT).

        Returns:
            list[list[int]]: 16x16 matrix where DDT[input_diff][output_diff] = propagation frequency.
        """
        ddt = [[0] * 16 for _ in range(16)]
        for input_diff in range(16):
            for x_val in range(16):
                dx = input_diff
                y_val = self.sbox_list[x_val]
                y_xor_dy = self.sbox_list[x_val ^ dx]
                ddt[dx][y_val ^ y_xor_dy] += 1
        return ddt

    def _evaluate_trail(self, start_diff: int, round_num: int) -> tuple[int, float, float]:
        """
        Greedily evaluates the probability of a differential characteristic (trail).

        Args:
            start_diff (int): The 16-bit initial input difference (ΔX).
            round_num (int): The number of rounds to evaluate.

        Returns:
            tuple[int, float, float]: Tuple containing:
                - final_xor (int): Expected output difference.
                - probability (float): Overall probability of the characteristic.
                - preference (float): Weighted probability penalizing 3 or 4 active S-boxes.
        """
        probability = 1.0
        current_bits = Bits(f"{start_diff:016b}")

        for _ in range(round_num):
            for idx in range(4):
                nibble = current_bits.get_nibble(idx)
                if nibble > 0:
                    max_count = max(self.ddt[nibble])
                    best_out_diff = self.ddt[nibble].index(max_count)
                    probability *= max_count / 16.0
                    current_bits = current_bits.set_nibble(idx, best_out_diff)

            current_bits = spn.p_box(current_bits, spn.heys_p_matrix)

        active_sboxes = sum(1 for i in range(4) if current_bits.get_nibble(i) > 0)
        preference = probability / (4 if active_sboxes == 3 else 1) if active_sboxes < 4 else 0.0
        return current_bits.to_int(), probability, preference

    def get_highly_probable_trails(self, round_num: int) -> list[tuple[float, float, int, int]]:
        """
        Computes all highly probable differential characteristics for a specific round length.

        Args:
            round_num (int): Number of active rounds for the characteristic.

        Returns:
            list[tuple[float, float, int, int]]: Sorted list containing (preference, probability, input_diff, output_diff).
        """
        trails = []
        for input_diff in range(1, 0x10000):  # intervall: [1, 0xFFFF]
            out_diff, prob, pref = self._evaluate_trail(input_diff, round_num)
            if pref > 0.0:
                trails.append((pref, prob, input_diff, out_diff))
        return sorted(trails, reverse=True)

    @staticmethod
    def find_trail_combinations(trails: list[tuple]) -> list[tuple]:
        """
        Selects a minimal combination of trails that collectively activate all 4 S-boxes.

        Args:
            trails (list[tuple]): List of available differential trails.

        Returns:
            list[tuple]: Subset of trails needed to break all subkey bits of a round.
        """
        useful_trails = []
        sbox_covered = [False] * 4

        for trail in trails:
            _, _, _, out_diff = trail
            useful = False
            for i in range(4):
                if ((out_diff >> (12 - i * 4)) & 0xF) > 0 and not sbox_covered[i]:
                    sbox_covered[i] = True
                    useful = True
            if useful:
                useful_trails.append(trail)
            if all(sbox_covered):
                break
        return useful_trails

    @staticmethod
    def get_active_key_mask(output_diff: int, round_idx: int) -> int:
        """
        Determines the 16-bit mask targeting the active subkey bits based on the expected output difference.

        Args:
            output_diff (int): Expected output difference of the trail.
            round_idx (int): Current target round (0-indexed).

        Returns:
            int: 16-bit mask with 1s at positions of active subkey bits.
        """
        mask = 0
        for i in range(4):
            if ((output_diff >> (12 - i * 4)) & 0xF) > 0:
                mask |= (0xF << (12 - i * 4))

        if round_idx < 3:
            mask = spn.p_box(Bits(f"{mask:016b}"), spn.heys_p_matrix).to_int()
        return mask

    def _peel_cipher(self, ciphertext: int, round_keys: list[int], target_round: int) -> int:
        """
        Partially decrypts the ciphertext up to the specified target round.

        Args:
            ciphertext (int): 16-bit block to decrypt.
            round_keys (list[int]): Array of known subkeys.
            target_round (int): Round index to peel back to.

        Returns:
            int: Partially decrypted 16-bit state.
        """
        state = ciphertext
        for r in range(4, target_round, -1):
            state ^= round_keys[r]
            if r < 4:
                state = spn.inverse_p_box(Bits(f"{state:016b}"), spn.heys_p_matrix).to_int()

            new_state = 0
            for i in range(4):
                nibble = (state >> (12 - i * 4)) & 0xF
                new_state |= (self.inverse_sbox_list[nibble] << (12 - i * 4))
            state = new_state
        return state

    def extract_partial_subkey(self, oracle: callable, trail: tuple, mask: int, target_round: int,
                               known_keys=None, return_hits: bool = False) -> list[int]:
        """
        Extracts highly probable candidates for specific subkey bits using a single differential trail.

        Args:
            oracle (callable): Function returning 16-bit ciphertext for 16-bit plaintext.
            trail (tuple): The applied differential characteristic.
            mask (int): Active subkey bit mask.
            target_round (int): Index of the round being attacked.
            known_keys (list[int]): Current state of successfully extracted subkeys.

        Returns:
            list[int]: Top 3 most probable values for the targeted partial subkey.
        """
        if known_keys is None:
            known_keys = [0] * 5
        _, probability, in_diff, out_diff = trail
        num_pairs = int(self.expected_right_pairs / probability)

        hits = {}
        pairs = []
        for _ in range(num_pairs):
            p1 = random.randint(0, 0xFFFF)
            c1 = oracle(p1)
            c2 = oracle(p1 ^ in_diff)
            pairs.append((c1, c2))

        active_shifts = [i for i in range(16) if (mask >> i) & 1]
        for k_guess_bits in itertools.product([0, 1], repeat=len(active_shifts)):
            k_guess = 0
            for bit_val, shift in zip(k_guess_bits, active_shifts):
                k_guess |= (bit_val << shift)

            known_keys[target_round + 1] = k_guess
            hit_count = 0
            for c1, c2 in pairs:
                v1 = self._peel_cipher(c1, known_keys, target_round)
                v2 = self._peel_cipher(c2, known_keys, target_round)
                if (v1 ^ v2) == out_diff:
                    hit_count += 1

            if hit_count > 0:
                hits[k_guess] = hit_count

        sorted_candidates = sorted(hits.items(), key=lambda x: x[1], reverse=True)
        return sorted_candidates

    def _break_first_round_key(self, oracle: callable, known_keys: list[int]) -> int:
        """
        Deterministically extracts K1 by fully decrypting a single ciphertext and XORing with its plaintext.

        Args:
            oracle (callable): Function returning 16-bit ciphertext for 16-bit plaintext.
            known_keys (list[int]): Array containing the already broken subkeys (K2-K5).

        Returns:
            int: The 16-bit first round subkey (K1).
        """
        plaintext = random.randint(0, 0xFFFF)
        ciphertext = oracle(plaintext)
        decrypted_state = self._peel_cipher(ciphertext, known_keys, 0)
        return plaintext ^ decrypted_state

    @staticmethod
    def merge_key_candidates(partial_candidates: list[tuple[int, list[int]]]) -> list[int]:
        """
        merges partial subkey hypotheses using bitwise intersection to resolve ambiguities.

        Args:
            partial_candidates (list[tuple[int, list[int]]]): list containing tuples of (active_mask, candidate_list).

        Returns:
            list[int]: mathematically valid full subkey candidates that satisfy all partial masks.

        Raises:
            ValueError: if no valid intersection exists.
        """
        full_key_hypotheses = []

        # iteriere durch das kartesische produkt aller partiellen kandidaten
        for combo in itertools.product(*[c for _, c in partial_candidates]):
            merged_key = 0
            valid = True

            # validiere schnittmengen auf inkonsistenzen
            for (mask_i, _), cand_i in zip(partial_candidates, combo):
                overlap = merged_key & mask_i
                if overlap > 0 and (merged_key & overlap) != (cand_i & overlap):
                    valid = False
                    break
                merged_key |= cand_i

            if valid:
                full_key_hypotheses.append(merged_key)

        if not full_key_hypotheses:
            raise ValueError("kein valider kandidat fuer subkey aus den schnittmengen gefunden.")

        return full_key_hypotheses

    def recover_remaining_layers(self, oracle: callable, known_keys: list[int]) -> tuple[int, int]:
        """
        executes phase 2 of the complete break: algebraically recovers k2 and k1 
        by exploiting the linear relationship delta_u2 = delta_w1.
        """

        # k1-kandidaten pro nibble tracken. wir nutzen schnittmengen aus mehreren
        # paaren, um "ghost-hits" der s-box auszufiltern.
        k1_candidates = [set(range(16)) for _ in range(4)]

        pairs = []
        # 4 paare sind statistisch mehr als genug, um k1 absolut eindeutig zu machen
        for _ in range(4):
            p1 = random.randint(0, 0xFFFF)
            p2 = random.randint(0, 0xFFFF)
            c1, c2 = oracle(p1), oracle(p2)
            pairs.append((p1, p2, c1, c2))

        for p1, p2, c1, c2 in pairs:
            # 1. target_round=1 entschluesselt c1/c2 rueckwaerts exakt durch k5, k4, k3
            # rueckgabe von _peel_cipher ist der zustand u2 (vor s-box in runde 2)
            u2_1 = self._peel_cipher(c1, known_keys, 1)
            u2_2 = self._peel_cipher(c2, known_keys, 1)

            # 2. anwendung deines beweis: delta u2 = u2_1 ^ u2_2
            delta_u2 = u2_1 ^ u2_2

            # gemaess theorie: delta u2 eliminiert k2 und entspricht exakt delta w1
            delta_w1 = delta_u2

            # 3. delta v1 berechnen (inverse p-box von delta w1)
            delta_v1 = self.spn.inverse_p_box(Bits(f"{delta_w1:016b}"), self.spn.heys_p_matrix).to_int() if hasattr(
                self, 'spn') else spn.inverse_p_box(Bits(f"{delta_w1:016b}"), spn.heys_p_matrix).to_int()

            # 4. k1 lokal pro s-box (nibble) ueber bruteforce isolieren
            for i in range(4):
                shift = 12 - i * 4
                p1_nibble = (p1 >> shift) & 0xF
                p2_nibble = (p2 >> shift) & 0xF
                dv1_nibble = (delta_v1 >> shift) & 0xF

                valid_guesses = set()
                for k_guess in range(16):
                    # pruefe s-box bedingung: S(P1 ^ K) ^ S(P2 ^ K) == delta V1
                    v1_1 = self.sbox_list[p1_nibble ^ k_guess]
                    v1_2 = self.sbox_list[p2_nibble ^ k_guess]

                    if (v1_1 ^ v1_2) == dv1_nibble:
                        valid_guesses.add(k_guess)

                # bilde schnittmenge der validen keys mit den vorherigen paaren
                k1_candidates[i] &= valid_guesses

        # 5. k1 aus den eindeutigen nibbles zusammensetzen
        k1 = 0
        for i in range(4):
            if not k1_candidates[i]:
                raise ValueError(f"inkonsistenz in phase 2: kein valider k1-kandidat an s-box {i + 1} gefunden.")

            # durch die schnittmenge bleibt exakt ein korrekter kandidat uebrig
            k1_nibble = list(k1_candidates[i])[0]
            k1 |= (k1_nibble << (12 - i * 4))

        # 6. k2 berechnen ueber umformung: u2 = w1 ^ k2 => k2 = u2 ^ w1
        p1, _, c1, _ = pairs[0]
        u2_1 = self._peel_cipher(c1, known_keys, 1)

        # w1 durch vorwaertsrechnung (P1 -> K1 -> S-Box -> P-Box) ermitteln
        u1_1 = p1 ^ k1
        v1_1 = 0
        for i in range(4):
            nibble = (u1_1 >> (12 - i * 4)) & 0xF
            v1_1 |= (self.sbox_list[nibble] << (12 - i * 4))

        w1_1 = self.spn.p_box(Bits(f"{v1_1:016b}"), self.spn.heys_p_matrix).to_int() if hasattr(self, 'spn') else spn.p_box(Bits(f"{v1_1:016b}"), spn.heys_p_matrix).to_int()

        k2 = u2_1 ^ w1_1

        return k1, k2

    def execute_complete_break(self, oracle_encrypt: callable, descriptive: bool = False) -> list[int]:
        """
        executes the complete key recovery attack on the spn cipher.
        """
        # initialisiere subkey liste (laenge 5: k1 bis k5 liegen sicher auf indizes 0 bis 4)
        extracted_keys = [0] * (self.num_rounds + 1)

        # phase 1: iterative target partial subkey extraktion fuer k5, k4, k3
        # target_round durchlaeuft 3, 2, 1 (0-indexed offset fuer runden 4, 3, 2)
        for target_round in range(self.num_rounds - 1, 0, -1):
            k_idx = target_round + 1  # 4, 3, 2 -> greift exakt auf k5, k4, k3 im array zu

            if descriptive:
                print(f"--- 1. darstellung der angewandten trails (k{k_idx + 1}) ---")
                print("--- 2. hit-counting pro trail ---")

            # berechne highly probable differential trails
            trails = self.get_highly_probable_trails(round_num=target_round)
            active_trails = self.find_trail_combinations(trails)

            partial_candidates = []
            for i, trail in enumerate(active_trails):
                # isoliere target partial subkey bits mittels bitmask
                mask = self.get_active_key_mask(trail[3], target_round)

                # fuehre partial decryption und hit-counting aus
                # target_round (3, 2, 1) wird sauber an extraktion und _peel_cipher uebergeben
                candidates_with_hits = self.extract_partial_subkey(
                    oracle=oracle_encrypt,
                    trail=trail,
                    mask=mask,
                    target_round=target_round,
                    known_keys=extracted_keys
                )

                # isoliere pure subkey kandidaten fuer consistency check
                pure_candidates = [k for k, _ in candidates_with_hits]
                partial_candidates.append((mask, pure_candidates))

                if descriptive:
                    top_3 = [f"0x{k:04X} ({hits} hits)" for k, hits in candidates_with_hits[:3]]
                    print(f"trail {i + 1} -> top 3: {top_3}")

            # merge independent partial subkeys via intersection logik
            full_candidates = self.merge_key_candidates(partial_candidates)
            extracted_keys[k_idx] = full_candidates[0]

            if descriptive:
                print(f"\n--- 3. finales resultat (K{k_idx + 1}) ---")
                print(f"nach merge logik: subkey prediction{k_idx + 1}: 0x{extracted_keys[k_idx]:04X}\n")

        # phase 2: algebraische eliminierung von k2 und k1
        if descriptive:
            print("--- SWITCH IN PHASE 2, d.h. (K2 & K1) ---")

        extracted_keys[0], extracted_keys[1] = self.recover_remaining_layers(
            oracle=oracle_encrypt,
            known_keys=extracted_keys
        )

        if descriptive:
            print(f"subkey prediction k2: 0x{extracted_keys[1]:04X}")
            print(f"subkey prediction k1: 0x{extracted_keys[0]:04X}\n")

        # rueckgabe der extrahierten subkeys [k1, k2, k3, k4, k5]
        return extracted_keys
