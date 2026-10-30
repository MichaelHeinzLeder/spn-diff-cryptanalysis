"""4-round Substitution-Permutation Network (SPN) and differential cryptanalysis package."""

from .bits import Bits
from .diff_cryptanalysis import DifferentialAttack, Trail
from .oracle import EncryptionOracle, SubkeyVerificationResult
from . import spn

__all__ = [
    "Bits",
    "DifferentialAttack",
    "EncryptionOracle",
    "SubkeyVerificationResult",
    "Trail",
    "spn",
]
