"""Two-phase differential cryptanalysis engine for R-round Substitution-Permutation Networks."""

from __future__ import annotations

from collections.abc import Callable
import itertools
import random
from typing import TypeAlias

from modules import spn
from modules.bits import Bits

# (preference_score, propagation_probability, input_diff_16bit, output_diff_16bit)
Trail: TypeAlias = tuple[float, float, int, int]
OracleFn: TypeAlias = Callable[[int], int]


class DifferentialAttack:
    """Executes a complete chosen-plaintext differential attack on a 4-round 16-bit SPN.

    The attack proceeds in two phases:
        1. Iterative statistical partial decryption (K5 -> K4 -> K3) using minimal covers of
           high-probability (R-1)-round differential trails and bitwise candidate intersection.
        2. Algebraic elimination of K2 via the linear identity ΔU_2 = ΔW_1, followed by
           per-nibble S-box differential filtering to deterministically recover K1 and K2.
    """

    def __init__(self, expected_right_pairs: int = 4, num_rounds: int = 4) -> None:
        """Initializes the attack engine and precomputes S-box, DDT, and P-box lookup tables.

        Args:
            expected_right_pairs: Target number of right pairs `c` used to size the chosen-plaintext
                sample `N_D = int(c / P_D)` for statistical signal-to-noise separation.
            num_rounds: Total number of SPN rounds `R` (default: 4).
        """
        if expected_right_pairs <= 0:
            raise ValueError("expected_right_pairs must be positive")
        if num_rounds < 2:
            raise ValueError("num_rounds must be at least 2")

        self.expected_right_pairs: int = expected_right_pairs
        self.num_rounds: int = num_rounds
        self.sbox_list: list[int] = self._convert_sbox_to_arr(spn.heys_s_map)
        self.inverse_sbox_list: list[int] = self._invert_sbox(self.sbox_list)
        self.ddt: list[list[int]] = self._build_ddt()

        # Precompute best differential output and probability per 4-bit S-box input difference
        self._best_sbox_diff: list[tuple[int, float]] = [
            (self.ddt[dx].index(max(self.ddt[dx])), max(self.ddt[dx]) / 16.0)
            for dx in range(16)
        ]

    @staticmethod
    def _convert_sbox_to_arr(sbox_map: dict[str, str]) -> list[int]:
        """Converts a 4-bit binary-string S-box dictionary into a 16-element integer LUT."""
        sbox = [0] * 16
        for in_bits, out_bits in sbox_map.items():
            sbox[int(in_bits, 2)] = int(out_bits, 2)
        return sbox

    @staticmethod
    def _invert_sbox(sbox_list: list[int]) -> list[int]:
        """Computes the inverse 16-element S-box lookup table."""
        inverse_sbox = [0] * 16
        for idx, val in enumerate(sbox_list):
            inverse_sbox[val] = idx
        return inverse_sbox

    def _build_ddt(self) -> list[list[int]]:
        """Constructs the 16x16 Difference Distribution Table (DDT) for the 4-bit S-box.

        Returns:
            16x16 matrix where `ddt[dx][dy]` counts inputs `x` satisfying
            `S(x) ^ S(x ^ dx) == dy`.
        """
        ddt = [[0] * 16 for _ in range(16)]
        for dx in range(16):
            for x_val in range(16):
                dy = self.sbox_list[x_val] ^ self.sbox_list[x_val ^ dx]
                ddt[dx][dy] += 1
        return ddt

    def _evaluate_trail(self, start_diff: int, round_num: int) -> tuple[int, float, float]:
        """Greedily propagates a 16-bit input difference ΔX across `round_num` SPN rounds.

        Args:
            start_diff: Initial 16-bit input difference ΔX in [1, 0xFFFF].
            round_num: Number of SPN rounds to propagate through.

        Returns:
            Tuple `(output_diff, probability, preference)` where `preference` penalizes
            characteristics that activate 3 or 4 S-boxes in the target round.
        """
        probability = 1.0
        state = start_diff

        for _ in range(round_num):
            substituted = 0
            for idx in range(4):
                shift = idx << 2
                nibble = (state >> shift) & 0xF
                if nibble > 0:
                    best_out_diff, sbox_prob = self._best_sbox_diff[nibble]
                    probability *= sbox_prob
                    substituted |= best_out_diff << shift
            state = spn.permute_16bit_int(substituted)

        out_diff = state
        active_sboxes = sum(1 for i in range(4) if ((out_diff >> (i << 2)) & 0xF) > 0)
        if active_sboxes >= 4:
            preference = 0.0
        elif active_sboxes == 3:
            preference = probability / 4.0
        else:
            preference = probability

        return out_diff, probability, preference

    def get_highly_probable_trails(self, round_num: int) -> list[Trail]:
        """Enumerates all non-zero 16-bit input differences and ranks valid differential trails.

        Args:
            round_num: Number of rounds for the differential characteristic.

        Returns:
            Descending-sorted list of `(preference, probability, input_diff, output_diff)` tuples.
        """
        trails: list[Trail] = []
        for input_diff in range(1, 0x10000):
            out_diff, prob, pref = self._evaluate_trail(input_diff, round_num)
            if pref > 0.0:
                trails.append((pref, prob, input_diff, out_diff))
        return sorted(trails, reverse=True)

    @staticmethod
    def find_trail_combinations(trails: list[Trail]) -> list[Trail]:
        """Selects a greedy minimal subset of trails covering all four 4-bit S-box positions.

        Args:
            trails: Ranked differential trails from `get_highly_probable_trails`.

        Returns:
            Subset of trails whose output differences jointly activate all 4 S-boxes.
        """
        useful_trails: list[Trail] = []
        sbox_covered = [False] * 4

        for trail in trails:
            _, _, _, out_diff = trail
            newly_covered = False
            for i in range(4):
                if ((out_diff >> (12 - i * 4)) & 0xF) > 0 and not sbox_covered[i]:
                    sbox_covered[i] = True
                    newly_covered = True
            if newly_covered:
                useful_trails.append(trail)
            if all(sbox_covered):
                break
        return useful_trails

    @staticmethod
    def get_active_key_mask(output_diff: int, round_idx: int) -> int:
        """Computes the 16-bit mask isolating subkey bits connected to active S-boxes.

        Args:
            output_diff: Expected 16-bit output difference ΔY before the target round.
            round_idx: 0-indexed round being attacked (3 for K5, 2 for K4, 1 for K3).

        Returns:
            16-bit integer mask with 1s at active subkey bit positions.
        """
        mask = 0
        for i in range(4):
            if ((output_diff >> (12 - i * 4)) & 0xF) > 0:
                mask |= 0xF << (12 - i * 4)

        if round_idx < 3:
            mask = spn.p_box(Bits(f"{mask:016b}"), spn.heys_p_matrix).to_int()
        return mask

    def _peel_cipher(
        self, ciphertext: int, round_keys: list[int], target_round: int
    ) -> int:
        """Partially decrypts a 16-bit ciphertext backward from round 4 down to `target_round`.

        Args:
            ciphertext: 16-bit ciphertext block.
            round_keys: 5-element list of round subkeys `[K1, K2, K3, K4, K5]`.
            target_round: Round index to stop at (returns internal state `U_{target_round+1}`).

        Returns:
            16-bit partially decrypted state before the target round's S-box layer.
        """
        state = ciphertext
        for r in range(4, target_round, -1):
            state ^= round_keys[r]
            if r < 4:
                state = spn.permute_16bit_int(state)

            state = (
                (self.inverse_sbox_list[(state >> 12) & 0xF] << 12)
                | (self.inverse_sbox_list[(state >> 8) & 0xF] << 8)
                | (self.inverse_sbox_list[(state >> 4) & 0xF] << 4)
                | self.inverse_sbox_list[state & 0xF]
            )
        return state

    def extract_partial_subkey(
        self,
        oracle: OracleFn,
        trail: Trail,
        mask: int,
        target_round: int,
        known_keys: list[int] | None = None,
        return_hits: bool = False,  # noqa: ARG002 - retained for notebook signature compatibility
    ) -> list[tuple[int, int]]:
        """Ranks partial subkey hypotheses for `mask` using a single differential trail.

        Args:
            oracle: Chosen-plaintext encryption callable `encrypt(p: int) -> int`.
            trail: Tuple `(preference, probability, in_diff, out_diff)`.
            mask: 16-bit bitmask of active subkey bits.
            target_round: Round index being attacked.
            known_keys: Previously recovered subkeys `[K1..K5]`.
            return_hits: Reserved parameter for API compatibility.

        Returns:
            List of `(partial_key_guess, hit_count)` sorted in descending order of hits.
        """
        working_keys = [0] * 5 if known_keys is None else list(known_keys)
        _, probability, in_diff, out_diff = trail
        num_pairs = int(self.expected_right_pairs / probability)

        pairs: list[tuple[int, int]] = []
        for _ in range(num_pairs):
            p1 = random.randint(0, 0xFFFF)
            pairs.append((oracle(p1), oracle(p1 ^ in_diff)))

        active_shifts = [bit_idx for bit_idx in range(16) if (mask >> bit_idx) & 1]
        hits: dict[int, int] = {}

        for k_guess_bits in itertools.product((0, 1), repeat=len(active_shifts)):
            k_guess = 0
            for bit_val, shift in zip(k_guess_bits, active_shifts):
                k_guess |= bit_val << shift

            working_keys[target_round + 1] = k_guess
            hit_count = 0
            for c1, c2 in pairs:
                v1 = self._peel_cipher(c1, working_keys, target_round)
                v2 = self._peel_cipher(c2, working_keys, target_round)
                if (v1 ^ v2) == out_diff:
                    hit_count += 1

            if hit_count > 0:
                hits[k_guess] = hit_count

        return sorted(hits.items(), key=lambda item: item[1], reverse=True)

    def _break_first_round_key(self, oracle: OracleFn, known_keys: list[int]) -> int:
        """Recovers K1 directly by peeling a single known plaintext-ciphertext pair to round 0."""
        plaintext = random.randint(0, 0xFFFF)
        ciphertext = oracle(plaintext)
        decrypted_state = self._peel_cipher(ciphertext, known_keys, 0)
        return plaintext ^ decrypted_state

    @staticmethod
    def merge_key_candidates(
        partial_candidates: list[tuple[int, list[int]]],
    ) -> list[int]:
        """Combines partial subkey candidates across overlapping masks via bitwise consistency.

        Args:
            partial_candidates: Sequence of `(active_mask, ordered_candidate_list)` pairs.

        Returns:
            Ordered list of 16-bit subkeys consistent with all partial masks.

        Raises:
            ValueError: If no mutually consistent 16-bit subkey combination exists.
        """
        full_key_hypotheses: list[int] = []

        for combo in itertools.product(*(cands for _, cands in partial_candidates)):
            merged_key = 0
            covered_mask = 0
            valid = True

            for (mask_i, _), cand_i in zip(partial_candidates, combo):
                overlap = covered_mask & mask_i
                if overlap and (merged_key & overlap) != (cand_i & overlap):
                    valid = False
                    break
                merged_key |= cand_i
                covered_mask |= mask_i

            if valid:
                full_key_hypotheses.append(merged_key)

        if not full_key_hypotheses:
            raise ValueError(
                "No consistent 16-bit subkey candidate found from partial mask intersections."
            )

        return full_key_hypotheses

    def recover_remaining_layers(
        self, oracle: OracleFn, known_keys: list[int]
    ) -> tuple[int, int]:
        """Executes Phase 2: algebraically eliminates K2 via ΔU_2 = ΔW_1 to recover (K1, K2).

        Because `U_2 = W_1 ^ K_2`, any pair of states `(U_{2,1}, U_{2,2})` peeled through
        known subkeys `(K_5, K_4, K_3)` satisfies `U_{2,1} ^ U_{2,2} = W_{1,1} ^ W_{1,2}`.
        Inverting the first-round P-box yields `ΔV_1`, isolating each 4-bit nibble of `K_1`
        independently across 4 chosen plaintext pairs.

        Args:
            oracle: Chosen-plaintext encryption callable.
            known_keys: Subkey array containing recovered `[_, _, K3, K4, K5]`.

        Returns:
            Tuple `(K1, K2)` of 16-bit integers.

        Raises:
            ValueError: If nibble candidate intersection yields an empty set.
        """
        k1_candidates: list[set[int]] = [set(range(16)) for _ in range(4)]
        pairs: list[tuple[int, int, int, int]] = []

        for _ in range(4):
            p1 = random.randint(0, 0xFFFF)
            p2 = random.randint(0, 0xFFFF)
            pairs.append((p1, p2, oracle(p1), oracle(p2)))

        for p1, p2, c1, c2 in pairs:
            u2_1 = self._peel_cipher(c1, known_keys, 1)
            u2_2 = self._peel_cipher(c2, known_keys, 1)

            # Linear key elimination: ΔU_2 = (W_{1,1} ^ K_2) ^ (W_{1,2} ^ K_2) = ΔW_1
            delta_w1 = u2_1 ^ u2_2
            delta_v1 = spn.inverse_p_box(
                Bits(f"{delta_w1:016b}"), spn.heys_p_matrix
            ).to_int()

            for i in range(4):
                shift = 12 - i * 4
                p1_nibble = (p1 >> shift) & 0xF
                p2_nibble = (p2 >> shift) & 0xF
                dv1_nibble = (delta_v1 >> shift) & 0xF

                valid_guesses = {
                    k_guess
                    for k_guess in range(16)
                    if (
                        self.sbox_list[p1_nibble ^ k_guess]
                        ^ self.sbox_list[p2_nibble ^ k_guess]
                    )
                    == dv1_nibble
                }
                k1_candidates[i] &= valid_guesses

        k1 = 0
        for i in range(4):
            if not k1_candidates[i]:
                raise ValueError(
                    f"Phase 2 inconsistency: no valid K1 nibble candidate at S-box {i + 1}."
                )
            k1_nibble = next(iter(k1_candidates[i]))
            k1 |= k1_nibble << (12 - i * 4)

        # Recover K2 deterministically from a single pair: K_2 = U_2 ^ W_1
        p1, _, c1, _ = pairs[0]
        u2_1 = self._peel_cipher(c1, known_keys, 1)

        u1_1 = p1 ^ k1
        v1_1 = 0
        for i in range(4):
            nibble = (u1_1 >> (12 - i * 4)) & 0xF
            v1_1 |= self.sbox_list[nibble] << (12 - i * 4)

        w1_1 = spn.p_box(Bits(f"{v1_1:016b}"), spn.heys_p_matrix).to_int()
        k2 = u2_1 ^ w1_1

        return k1, k2

    def execute_complete_break(
        self, oracle_encrypt: OracleFn, descriptive: bool = False
    ) -> list[int]:
        """Executes the complete two-phase differential attack recovering `[K1, K2, K3, K4, K5]`.

        Args:
            oracle_encrypt: Black-box encryption function `oracle.encrypt`.
            descriptive: If True, prints per-round trail statistics and top candidate hits.

        Returns:
            List of five 16-bit integers `[K1, K2, K3, K4, K5]`.
        """
        extracted_keys = [0] * (self.num_rounds + 1)

        # Phase 1: Iterative statistical partial subkey extraction for K5, K4, K3
        for target_round in range(self.num_rounds - 1, 0, -1):
            k_idx = target_round + 1

            if descriptive:
                print(f"--- 1. Applied Differential Trails (K{k_idx + 1}) ---")
                print("--- 2. Hit-Counting per Trail ---")

            trails = self.get_highly_probable_trails(round_num=target_round)
            active_trails = self.find_trail_combinations(trails)

            partial_candidates: list[tuple[int, list[int]]] = []
            for idx, trail in enumerate(active_trails):
                mask = self.get_active_key_mask(trail[3], target_round)
                candidates_with_hits = self.extract_partial_subkey(
                    oracle=oracle_encrypt,
                    trail=trail,
                    mask=mask,
                    target_round=target_round,
                    known_keys=extracted_keys,
                )

                pure_candidates = [k for k, _ in candidates_with_hits]
                partial_candidates.append((mask, pure_candidates))

                if descriptive:
                    top_3 = [
                        f"0x{k:04X} ({hits} hits)"
                        for k, hits in candidates_with_hits[:3]
                    ]
                    print(f"Trail {idx + 1} -> Top 3: {top_3}")

            full_candidates = self.merge_key_candidates(partial_candidates)
            extracted_keys[k_idx] = full_candidates[0]

            if descriptive:
                print(f"\n--- 3. Merged Subkey Result (K{k_idx + 1}) ---")
                print(
                    f"Merged Subkey Prediction K{k_idx + 1}: 0x{extracted_keys[k_idx]:04X}\n"
                )

        # Phase 2: Algebraic recovery of K2 and K1
        if descriptive:
            print("--- Phase 2: Algebraic Elimination (K2 & K1) ---")

        extracted_keys[0], extracted_keys[1] = self.recover_remaining_layers(
            oracle=oracle_encrypt,
            known_keys=extracted_keys,
        )

        if descriptive:
            print(f"Subkey Prediction K2: 0x{extracted_keys[1]:04X}")
            print(f"Subkey Prediction K1: 0x{extracted_keys[0]:04X}\n")

        return extracted_keys
