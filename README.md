# spn-diff-cryptanalysis

Python and SageMath implementation and differential cryptanalysis of a 4-round, 16-bit Substitution-Permutation Network (SPN) based on Heys (2002), performing full 80-bit master key recovery ($K_1 \dots K_5$) via chosen-plaintext attack (CPA).

> Originally developed as my contribution to the final university project in *Applied Mathematics / Cryptography* (graded **1.0**). Full mathematical derivations and step-by-step walkthroughs are provided in [`Cryptanalysis.ipynb`](Cryptanalysis.ipynb).

## Architecture

- **Bit-Vector Primitive (`modules/bits.py`)**: Fixed and variable-width binary vector (`Bits`) supporting bitwise arithmetic (`XOR`, `OR`, `AND`, logical shifts), nibble addressing (`get_nibble`, `set_nibble`), and hexadecimal/ASCII/byte serialization.
- **4-Round SPN Cipher (`modules/spn.py`)**: Implements the 4-bit S-box ($\pi_S, \pi_S^{-1}$), 16-bit permutation matrix ($\pi_P, \pi_P^{-1}$ via SageMath `Matrix` with a pure-Python fallback), round key mixing, and full 4-round encryption/decryption over an 80-bit key schedule ($K_1 \dots K_5$).
- **Chosen-Plaintext Oracle (`modules/oracle.py`)**: Black-box CPA encryption oracle (`EncryptionOracle`) backed by a CSPRNG-generated 80-bit master key (`secrets.randbits(80)`) and subkey verification without key disclosure.
- **Differential Cryptanalysis Engine (`modules/diff_cryptanalysis.py`)**:
  - **Phase 1 (Statistical Partial Decryption — $K_5 \to K_4 \to K_3$)**: Constructs the $16 \times 16$ Difference Distribution Table (DDT), ranks $(R-1)$-round differential trails under the Markov cipher assumption, selects minimal S-box covers, and intersects partial subkey masks across chosen-plaintext pairs ($N_D \approx c / P_D$).
  - **Phase 2 (Algebraic Layer Elimination — $K_2 \text{ \& } K_1$)**: Exploits the linear key-mixing identity $\Delta U_2 = (W_{1,1} \oplus K_2) \oplus (W_{1,2} \oplus K_2) = \Delta W_1$ to eliminate $K_2$, isolates $K_1$ nibble-wise across 4 plaintext pairs via $\pi_P^{-1}(\Delta W_1) = \Delta V_1$, and recovers $K_2 = U_2 \oplus W_1$ deterministically.

```text
.
├── Cryptanalysis.ipynb
├── LICENSE
├── README.md
├── modules/
│   ├── __init__.py
│   ├── bits.py
│   ├── diff_cryptanalysis.py
│   ├── oracle.py
│   └── spn.py
└── tests/
    └── test_spn_cryptanalysis.py
```

## Attack Phases

| Phase | Target Subkeys | Method | Complexity / Sample Size |
| :--- | :--- | :--- | :--- |
| **Phase 1** | $K_5, K_4, K_3$ | $(R-1)$-round differential trails + partial decryption hit-counting & mask intersection | $N_D \approx c / P_D$ chosen-plaintext pairs per trail |
| **Phase 2** | $K_1, K_2$ | Algebraic $K_2$ elimination ($\Delta U_2 = \Delta W_1$) + $4 \times 2^4$ S-box nibble intersection | $4$ chosen-plaintext pairs (deterministic) |

## Dependencies

- Python $\ge 3.12$
- Optional: `sagemath` (for interactive table rendering and symbolic matrix types in [`Cryptanalysis.ipynb`](Cryptanalysis.ipynb); `modules/spn.py` includes a pure-Python fallback for standalone execution and `pytest`)
- `pytest` (for running the test suite)

## Usage & Verification

```bash
PYTHONPATH=. pytest -v
```

```python
from modules import DifferentialAttack, EncryptionOracle

oracle = EncryptionOracle()
attack = DifferentialAttack(expected_right_pairs=38)

extracted_keys = attack.execute_complete_break(oracle.encrypt, descriptive=True)
assert oracle.is_complete_break_successful(extracted_keys)
```
