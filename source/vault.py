import os
import struct
from source.keys import derive_key, encrypt_data, decrypt_data

MAGIC_BYTES = b"LOCK"

class VaultManager:
    def __init__(self, vault_path):
        self.vault_path = vault_path

    def init_vault(self, password):
        """Initialise un nouveau vault avec un header."""
        if os.path.exists(self.vault_path):
            raise FileExistsError("Le vault existe déjà.")

        salt = os.urandom(16)
        key = derive_key(password, salt)
        # On crée une clé de vérification pour valider le mot de passe sans déchiffrer tout
        verifier = encrypt_data(b"VERIFY", key)

        with open(self.vault_path, "wb") as f:
            f.write(MAGIC_BYTES)
            f.write(salt)
            # Écrire la taille du verifier (I = 4 octets)
            f.write(struct.pack("I", len(verifier)))
            f.write(verifier)

    def _get_key(self, password):
        with open(self.vault_path, "rb") as f:
            f.read(4) # Magic
            salt = f.read(16)
            # Lire la taille du verifier
            verifier_len = struct.unpack("I", f.read(4))[0]
            f.read(verifier_len) # Skip verifier
            return derive_key(password, salt)

    def list_files(self):
        """Liste les noms de fichiers dans le vault."""
        files = []
        if not os.path.exists(self.vault_path):
            return files
        with open(self.vault_path, "rb") as f:
            f.read(4) # Magic
            f.read(16) # Salt
            verifier_len = struct.unpack("I", f.read(4))[0]
            f.read(verifier_len) # Skip verifier

            while True:
                name_len_data = f.read(4)
                if not name_len_data: break
                name_len = struct.unpack("I", name_len_data)[0]

                # 'replace' évite le crash si décodage UTF-8 impossible
                name = f.read(name_len).decode(errors='replace')

                # Lecture sûre de la taille des données
                data_len_data = f.read(8)
                if len(data_len_data) < 8: break # Fin de fichier inattendue
                data_len = struct.unpack("Q", data_len_data)[0]

                f.read(data_len) # Skip data
                files.append(name)
        return files

    def add_file(self, filepath, password):
        """Ajoute un fichier au vault avec vérification d'existence."""
        filename = os.path.basename(filepath)

        # Vérification doublon
        if filename in self.list_files():
            raise Exception("Fichier déjà existant")

        key = self._get_key(password)
        with open(filepath, "rb") as f:
            data = f.read()

        encrypted_data = encrypt_data(data, key)

        with open(self.vault_path, "ab") as f:
            f.write(struct.pack("I", len(filename.encode())))
            f.write(filename.encode())
            f.write(struct.pack("Q", len(encrypted_data)))
            f.write(encrypted_data)
