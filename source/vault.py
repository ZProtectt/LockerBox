import json
import os
import struct
import time

from source.crypto import derive_key, encrypt_data, decrypt_data
from cryptography.exceptions import InvalidTag


class IntegrityError(Exception):
    """Levée quand le tag AES-GCM échoue : mauvais mot de passe ou fichier altéré."""
    pass


# ─── Constantes de format du fichier .lbox ─────────────────────────────────
# Octet 0-3  : magic "LBOX"
# Octet 4    : version 0x01
# Octet 5-20 : sel Argon2 (16 octets)
# Octet 21-24: longueur de l'index chiffré (uint32 little-endian)
# Octet 25+  : index chiffré (nonce+ciphertext+tag AES-GCM)
# Suite      : blobs des fichiers (nonce+ciphertext+tag AES-GCM chacun)
HEADER_SIZE = 25  # 4 (magic) + 1 (version) + 16 (salt) + 4 (index_len)
MAGIC = b"LBOX"
VERSION = b"\x01"


class Vault:
    """Coffre-fort chiffré : gère la création, l'ouverture et les opérations sur fichiers."""

    MAX_ATTEMPTS = 3
    LOCK_DURATION = 30  # secondes

    def __init__(self, vault_path: str, password: str):
        self.vault_path = vault_path
        self.password = password
        self.index: dict = {"files": {}}
        self.salt: bytes | None = None
        # Clé de données : aléatoire, protégée par wrapped_key dans l'index
        self.key: bytes | None = None
        # Anti-bruteforce : état de session uniquement
        self.failed_attempts = 0
        self.locked_until = 0.0

    # ──────────────────────────────────────────────────────────────────────
    # Primitives bas niveau
    # ──────────────────────────────────────────────────────────────────────

    def _derive_password_key(self, salt: bytes) -> bytes:
        """Dérive la clé à partir du mot de passe et du sel via Argon2id."""
        return derive_key(self.password, salt)

    def _build_index_payload(self, password_key: bytes) -> bytes:
        """Sérialise l'index avec la wrapped_key prête à être chiffrée."""
        return json.dumps({
            **self.index,
            "wrapped_key": encrypt_data(password_key, self.key).hex(),
        }).encode()

    def _recompute_offsets(self, password_key: bytes) -> None:
        """Recalcule les offsets absolus de chaque fichier dans le vault.

        On itère deux fois : la taille de l'index dépend des offsets, et les
        offsets dépendent de la taille de l'index. Deux passes suffisent à la
        convergence car la taille numérique des entiers est bornée.
        """
        for _ in range(2):
            sample_index = encrypt_data(password_key, self._build_index_payload(password_key))
            base = HEADER_SIZE + len(sample_index)
            ptr = 0
            for info in self.index["files"].values():
                info["offset"] = base + ptr
                ptr += info["size"]

    def _read_file_blobs(self) -> bytes:
        """Relit tous les blobs chiffrés existants dans l'ordre de l'index."""
        blobs = bytearray()
        with open(self.vault_path, "rb") as f:
            for info in self.index["files"].values():
                f.seek(info["offset"])
                blobs.extend(f.read(info["size"]))
        return bytes(blobs)

    def _write_vault(self, blobs: bytes) -> None:
        """Écrit le fichier vault complet : header + index chiffré + blobs."""
        password_key = self._derive_password_key(self.salt)
        self._recompute_offsets(password_key)
        encrypted_index = encrypt_data(password_key, self._build_index_payload(password_key))
        with open(self.vault_path, "wb") as f:
            f.write(MAGIC + VERSION + self.salt)
            f.write(struct.pack("<I", len(encrypted_index)))
            f.write(encrypted_index)
            f.write(blobs)

    # ──────────────────────────────────────────────────────────────────────
    # Opérations principales
    # ──────────────────────────────────────────────────────────────────────

    def create_vault(self) -> None:
        """Crée un nouveau vault vide."""
        self.salt = os.urandom(16)
        self.key = os.urandom(32)
        self.index = {"files": {}}
        self._write_vault(b"")

    def load_vault(self) -> None:
        """Charge et déchiffre l'index du vault. Lève IntegrityError si le mot de passe est faux."""
        if not os.path.exists(self.vault_path):
            raise FileNotFoundError("Vault non trouvé.")

        with open(self.vault_path, "rb") as f:
            magic = f.read(4)
            f.read(1)  # version
            self.salt = f.read(16)
            index_len = struct.unpack("<I", f.read(4))[0]

            if magic != MAGIC:
                raise ValueError("Format de fichier inconnu.")

            password_key = self._derive_password_key(self.salt)
            try:
                encrypted_index = f.read(index_len)
                index_data = decrypt_data(password_key, encrypted_index)
                self.index = json.loads(index_data.decode())
                wrapped_key_hex = self.index.pop("wrapped_key", None)
                self.key = (
                    decrypt_data(password_key, bytes.fromhex(wrapped_key_hex))
                    if wrapped_key_hex
                    else password_key
                )
            except (InvalidTag, ValueError, json.JSONDecodeError):
                raise IntegrityError("Mot de passe incorrect ou vault corrompu.")

    def list_files(self) -> list[str]:
        """Retourne la liste des noms de fichiers stockés dans le vault."""
        self.load_vault()
        return list(self.index["files"].keys())

    def add_file(self, file_path: str) -> None:
        """Chiffre et ajoute un fichier dans le vault."""
        if os.path.exists(self.vault_path):
            self.load_vault()
            blobs = self._read_file_blobs()
        else:
            self.create_vault()
            blobs = b""

        with open(file_path, "rb") as f:
            plaintext = f.read()

        encrypted = encrypt_data(self.key, plaintext)
        name = os.path.basename(file_path)
        self.index["files"][name] = {"size": len(encrypted), "offset": 0}
        self._write_vault(blobs + encrypted)

    def extract_file(self, filename: str, output_path: str) -> None:
        """Déchiffre et écrit un fichier du vault vers output_path."""
        self.load_vault()
        if filename not in self.index["files"]:
            raise FileNotFoundError(f"Fichier '{filename}' non trouvé.")

        info = self.index["files"][filename]
        with open(self.vault_path, "rb") as f:
            f.seek(info["offset"])
            encrypted = f.read(info["size"])

        try:
            plaintext = decrypt_data(self.key, encrypted)
        except (InvalidTag, ValueError):
            raise IntegrityError(f"Le fichier '{filename}' est corrompu.")

        with open(output_path, "wb") as f:
            f.write(plaintext)

    def delete_file(self, filename: str) -> None:
        """Supprime un fichier du vault en réécrivant uniquement les blobs restants."""
        self.load_vault()
        if filename not in self.index["files"]:
            raise FileNotFoundError(f"Fichier '{filename}' non trouvé.")

        # Lire les blobs à conserver avant de modifier l'index
        remaining_blobs = bytearray()
        with open(self.vault_path, "rb") as f:
            for name, info in self.index["files"].items():
                if name != filename:
                    f.seek(info["offset"])
                    remaining_blobs.extend(f.read(info["size"]))

        del self.index["files"][filename]
        self._write_vault(bytes(remaining_blobs))

    def change_password(self, new_password: str) -> None:
        """Change le mot de passe sans rechiffrer les fichiers.

        Seule la wrapped_key (enveloppe de la clé de données) est recréée.
        Les blobs des fichiers restent inchangés.
        """
        if not isinstance(new_password, str) or not new_password:
            raise ValueError("Le nouveau mot de passe est requis.")

        self.load_vault()
        blobs = self._read_file_blobs()

        self.password = new_password
        self.salt = os.urandom(16)
        self._write_vault(blobs)

    # ──────────────────────────────────────────────────────────────────────
    # Protection anti-bruteforce (état de session)
    # ──────────────────────────────────────────────────────────────────────

    def is_locked(self) -> bool:
        """Retourne True si le vault est temporairement verrouillé."""
        return time.time() < self.locked_until

    def register_failed_attempt(self) -> None:
        """Enregistre un échec et verrouille si le seuil est atteint."""
        self.failed_attempts += 1
        if self.failed_attempts >= self.MAX_ATTEMPTS:
            self.locked_until = time.time() + self.LOCK_DURATION

    def reset_bruteforce(self) -> None:
        """Réinitialise le compteur après une authentification réussie."""
        self.failed_attempts = 0
        self.locked_until = 0.0
