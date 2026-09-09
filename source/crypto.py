import os

from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


NONCE_SIZE = 12          # Taille du nonce pour AES-GCM
SALT_SIZE = 16           # Sel de 128 bits pour Argon2

def derive_key(password: str, salt: bytes, key_length: int = 32) -> bytes:
    # Derive une clé à partir d'un mot de passe et d'un sel en utilisant Argon2id.

    if not isinstance(password, str):
        raise TypeError("Le mot de passe doit être une chaîne.")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_SIZE:
        raise ValueError("Le sel doit faire 16 octets.")
    if key_length != 32:
        raise ValueError("Seule une clé de 32 octets est supportée.")
    
    # Utilisation de la fonction hash_secret_raw.
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
    # Chiffre des données avec AES-256-GCM et retourne (nonce + ciphertext + tag).

    if len(key) != 32:
        raise ValueError("La clé doit faire 32 octets.")

    # On génère un nonce aléatoire pour AES-GCM et on chiffre les données.
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)  

    # On chiffre les données avec le nonce généré. Le tag est automatiquement ajouté à la fin du ciphertext.   
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext               


def decrypt_data(key: bytes, payload: bytes) -> bytes:
    # Déchiffre les données avec AES-256-GCM. Le payload doit contenir (nonce + ciphertext + tag).

    if len(payload) < NONCE_SIZE + 16:
        raise ValueError("Tampering détecté : payload trop court.")

    # On sépare le nonce et le ciphertext du payload.
    aesgcm = AESGCM(key)
    nonce = payload[:NONCE_SIZE]         
    ciphertext = payload[NONCE_SIZE:]   

    # On utilise un bloc try pour capturer les erreurs de déchiffrement dues à un tag invalide.
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        # Le tag AES-GCM est invalide et don données corrompues ou mauvaise clé
        raise ValueError("Tampering détecté.") from exc
