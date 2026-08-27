import os

from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12
SALT_SIZE = 16


def derive_key(password: str, salt: bytes, key_length: int = 32) -> bytes:
    """Derive une cle AES-256 depuis le mot de passe via Argon2id.

    Parametres Argon2id choisis pour resister a la force brute :
    time_cost=3, memory_cost=64 Mo, parallelism=4.
    """
    if not isinstance(password, str):
        raise TypeError("Le mot de passe doit etre une chaine.")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_SIZE:
        raise ValueError("Le sel doit faire 16 octets.")
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=bytes(salt),
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=key_length,
        type=Type.ID,
    )


def encrypt_data(key: bytes, data: bytes) -> bytes:
    """Chiffre data avec AES-256-GCM.

    Retourne nonce (12 octets) + ciphertext + tag (16 octets).
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext


def decrypt_data(key: bytes, payload: bytes) -> bytes:
    """Dechiffre un payload AES-256-GCM.

    Leve ValueError si le tag est invalide (mauvaise cle ou donnees alterees).
    """
    if len(payload) < NONCE_SIZE + 16:
        raise ValueError("Tampering detecte : payload trop court.")
    aesgcm = AESGCM(key)
    nonce = payload[:NONCE_SIZE]
    ciphertext = payload[NONCE_SIZE:]
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise ValueError("Tampering detecte.") from exc
