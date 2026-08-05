import json
import os
import struct
from crypto import derive_key, encrypt_data, decrypt_data
from cryptography.exceptions import InvalidTag

class IntegrityError(Exception):
    """Exception levée quand le tag d'intégrité ne correspond pas."""
    pass

class Vault:
    MAGIC = b"LBOX"
    VERSION = b"\x01"

    def __init__(self, vault_path, password):
        self.vault_path = vault_path
        self.password = password
        self.index = {"files": {}}
        self.salt = None
        self.key = None

    def _get_key(self, salt):
        return derive_key(self.password, salt)

    def create_vault(self):
        self.salt = os.urandom(16)
        self.key = self._get_key(self.salt)
        self.index = {"files": {}}
        self._save_vault(b"")

    def _save_vault(self, all_data):
        index_data = json.dumps(self.index).encode()
        encrypted_index = encrypt_data(self.key, index_data)
        index_len = len(encrypted_index)

        with open(self.vault_path, 'wb') as f:
            f.write(self.MAGIC + self.VERSION + self.salt)
            f.write(struct.pack('<I', index_len))
            f.write(encrypted_index)
            f.write(all_data)
        print(f"DEBUG: Vault sauvegardé. IndexLen={index_len}, DataLen={len(all_data)}")

    def load_vault(self):
        if not os.path.exists(self.vault_path):
            raise FileNotFoundError("Vault non trouvé.")
        with open(self.vault_path, 'rb') as f:
            magic = f.read(4)
            f.read(1) # Skip version
            self.salt = f.read(16)
            index_len = struct.unpack('<I', f.read(4))[0]

            if magic != self.MAGIC:
                raise ValueError("Format de fichier inconnu.")

            self.key = self._get_key(self.salt)
            try:
                encrypted_index = f.read(index_len)
                index_data = decrypt_data(self.key, encrypted_index)
                self.index = json.loads(index_data.decode())
            except InvalidTag:
                raise IntegrityError("L'index du vault est corrompu (tampering détecté).")

    def list_files(self):
        self.load_vault()
        return list(self.index["files"].keys())

    def add_file(self, file_path):
        all_data = b""
        if os.path.exists(self.vault_path):
            self.load_vault()
            with open(self.vault_path, 'rb') as f:
                f.seek(21)
                index_len = struct.unpack('<I', f.read(4))[0]
                f.seek(25 + index_len)
                all_data = f.read()
        else:
            self.create_vault()

        with open(file_path, 'rb') as f:
            new_data = f.read()
        encrypted_new_data = encrypt_data(self.key, new_data)

        name = os.path.basename(file_path)
        self.index["files"][name] = {"size": len(encrypted_new_data)}
        all_data += encrypted_new_data

        # Calculer les offsets
        index_data = json.dumps(self.index).encode()
        # On utilise une version temporaire pour calculer la taille sans écraser le nonce
        # Important : le nonce aléatoire change, la taille doit rester la même.
        encrypted_index_for_size = encrypt_data(self.key, index_data)

        current_offset = 25 + len(encrypted_index_for_size)

        # Calcul des offsets
        data_ptr = 0
        for fname in self.index["files"]:
            self.index["files"][fname]["offset"] = current_offset + data_ptr
            data_ptr += self.index["files"][fname]["size"]
            print(f"DEBUG: File={fname}, Offset={self.index['files'][fname]['offset']}, Size={self.index['files'][fname]['size']}")

        self._save_vault(all_data)
        print(f"Fichier '{name}' ajouté.")

    def extract_file(self, filename, output_path):
        self.load_vault()
        if filename not in self.index["files"]:
            raise FileNotFoundError(f"Fichier '{filename}' non trouvé.")

        file_info = self.index["files"][filename]
        print(f"DEBUG: Extraction File={filename}, Offset={file_info['offset']}, Size={file_info['size']}")

        with open(self.vault_path, 'rb') as f:
            f.seek(file_info["offset"])
            encrypted_data = f.read(file_info["size"])

        try:
            data = decrypt_data(self.key, encrypted_data)
        except InvalidTag:
            raise IntegrityError(f"Le fichier '{filename}' est corrompu (tampering détecté).")

        with open(output_path, 'wb') as f:
            f.write(data)
