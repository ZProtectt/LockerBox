import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# Constants
NONCE_SIZE = 12
SALT_SIZE = 16

def derive_key(password: str, salt: bytes, key_length: int = 32) -> bytes:
    """
    Derives a key from a password using Argon2id.
    """
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=key_length,
        type=Type.ID
    )

def encrypt_data(key: bytes, data: bytes) -> bytes:
    """
    Encrypts data using AES-256-GCM.
    Returns: nonce (12 bytes) + ciphertext (includes tag)
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    # The cryptography library appends the 16-byte tag to the ciphertext automatically
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt_data(key: bytes, encrypted_data: bytes) -> bytes:
    """
    Decrypts data using AES-256-GCM.
    Expects: nonce (12 bytes) + ciphertext (includes tag)
    """
    nonce = encrypted_data[:NONCE_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE:]
    aesgcm = AESGCM(key)
    # If the tag is invalid (tampering detected), this will raise InvalidTag
    return aesgcm.decrypt(nonce, ciphertext, None)

if __name__ == "__main__":
    # 1. Test Argon2id
    password = "mon-super-mot-de-passe"
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)

    print(f"Key derived: {key.hex()}")

    # 2. Test Encryption/Decryption with derived key
    data = b"Ceci est un secret."
    encrypted = encrypt_data(key, data)
    decrypted = decrypt_data(key, encrypted)

    assert data == decrypted
    print("Succès : Le chiffrement avec la clé dérivée fonctionne.")

    # 3. Test Tampering
    tampered = bytearray(encrypted)
    tampered[-1] ^= 0x01 # Flip a bit in the tag

    print("\nTest de corruption (tampering)...")
    try:
        decrypt_data(key, bytes(tampered))
        print("ERREUR : Le déchiffrement a réussi alors qu'il aurait dû échouer.")
    except Exception as e:
        print(f"Succès : Le déchiffrement a échoué comme prévu ({type(e).__name__}).")

