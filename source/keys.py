import os
from argon2 import low_level
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# --- Constantes de Sécurité ---
# Paramètres Argon2id (Standard actuel : 64MB mémoire, 3 itérations)
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536
ARGON2_PARALLELISM = 4
KEY_SIZE = 32  # AES-256

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Dérive une clé de 32 octets depuis un mot de passe et un salt avec Argon2id.
    """
    return low_level.hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_SIZE,
        type=low_level.Type.ID
    )

def encrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Chiffre des données avec AES-256-GCM.
    Retourne : Nonce (12 octets) + Ciphertext + Tag (16 octets)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # Nonce sécurisé
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt_data(data: bytes, key: bytes) -> bytes:
    """
    Déchiffre des données avec AES-256-GCM.
    Lève InvalidTag si les données ont été altérées ou si la clé est mauvaise.
    """
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Erreur : Données altérées ou clé invalide (Tampering détecté).")
