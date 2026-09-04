"""API publique de LockerBox.

Les primitives cryptographiques viennent de ``crypto.py``. Les fonctions de
gestion du coffre sont dans ``vault.py``. Ces imports permettent d'utiliser
les elements principaux directement depuis ``source``.
"""

from source.crypto import derive_key, encrypt_data, decrypt_data
from source.vault import IntegrityError, LockedError, new_vault

__all__ = [
    'derive_key',
    'encrypt_data',
    'decrypt_data',
    'new_vault',
    'IntegrityError',
    'LockedError'
]