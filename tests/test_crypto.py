import pytest
import os
from source.keys import derive_key, encrypt_data, decrypt_data

def test_encryption_roundtrip():
    """Vérifie qu'un chiffrement suivi d'un déchiffrement rend les données initiales."""
    password = "SuperPassword123!"
    salt = os.urandom(16)
    key = derive_key(password, salt)

    data = b"Ceci est un message tres confidentiel."
    encrypted = encrypt_data(data, key)
    decrypted = decrypt_data(encrypted, key)

    assert data == decrypted

def test_tampering_detection():
    """Vérifie que la modification des données chiffrées lève une exception."""
    password = "AutrePassword456"
    salt = os.urandom(16)
    key = derive_key(password, salt)

    data = b"Donnees sensibles."
    encrypted = bytearray(encrypt_data(data, key))

    # Altération (Tampering) - modification du dernier octet du ciphertext
    encrypted[-1] ^= 0x01

    with pytest.raises(ValueError, match="Tampering détecté"):
        decrypt_data(bytes(encrypted), key)
