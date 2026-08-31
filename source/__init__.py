"""
Source package for LockerBox secure vault system.

This package contains the core cryptographic and vault management modules:
- crypto.py: Cryptographic primitives (key derivation, AES-GCM encryption)
- vault.py: Vault class handling file operations and anti-bruteforce protection
"""

from source.crypto import derive_key, encrypt_data, decrypt_data
from source.vault import Vault, IntegrityError, LockedError

__all__ = [
    'derive_key',
    'encrypt_data',
    'decrypt_data',
    'Vault',
    'IntegrityError',
    'LockedError'
]