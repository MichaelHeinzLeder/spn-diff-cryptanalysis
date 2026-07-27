# spn-diff-cryptanalysis

> *preface*  
> this repo contains MY contribution to our final university group project in *Applied Mathematics  > Cryptography*  
→ my part was graded with a **1.0**  
> → for everything we assume a **4-Round-SPN**

## About
This repository is meant to show an implementation and mathematical vulnerability analysis of an **SPN** through *differences!*
→ *complete break by chosen-plaintext-attack as goal*

## Modules
The project is built entirely in Python and utilizes SageMath for algebraic matrix operations; modularized as follows:

> **`spn.py`**   →
implements a full 4-round SPN block cipher

> **`diff_cryptanalysis.py`**   
contains the `DifferentialAttack` class, executing the core logic to break the cipher, e.g.:
  
  → automated generation of a 16x16 Difference Distribution Table
  
  → algorithm to *greedily* evaluate and construct highly probable $R-1$ round differential trails. 
> **`oracle.py`**  
simulates the attacker's environment via the `EncryptionOracle` class, returning ciphertexts for chosen plaintexts without revealing the randomly generated 80-bit master key  

> **`bits.py`:**   
defines a robust helper class for customized bitwise operations, logical shifts, and byte-array parsing.

## Crux

The `execute_complete_break` automatically extracts the full master key via a highly optimized, two-phase approach:

- *Phase 1: iterative partial decryption*
→ statistical extraction of partial subkeys up to full subkey
- *Phase 2: some algebra* 
→ deterministic break by linear relationship
---
**Note: EVERYTHING is explained in full detail within the accompanying notebook cryptanalysis.ipynb!**
