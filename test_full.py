from crypto import derive_key, encrypt_data, decrypt_data
import os

def run_integration_test():
    print("--- Lancement du test d'intégration ---")
    password = "test"
    salt = os.urandom(16)

    # 1. Dérivation
    print("Test Argon2id...")
    key = derive_key(password, salt)
    print("Argon2id OK.")

    # 2. Simulation de chiffrement
    print("Test AES-GCM...")
    original_data = b"Contenu secret du fichier"
    encrypted = encrypt_data(key, original_data)

    # 3. Simulation de dechiffrement
    decrypted = decrypt_data(key, encrypted)

    assert original_data == decrypted
    print("AES-GCM OK.")

    print("--- Test d'intégration complet REUSSI ! ---")

if __name__ == "__main__":
    try:
        run_integration_test()
    except Exception as e:
        print(f"Test échoué : {e}")
