"""Fonctions de gestion du coffre LockerBox.

Un vault est un fichier binaire compose d'un en-tete, d'un index chiffre et
des fichiers chiffres. Le module utilise un dictionnaire simple pour garder
l'etat du vault en memoire.
"""

import json
import os
import struct
import time

from source.crypto import SALT_SIZE, decrypt_data, derive_key, encrypt_data


# Ces alias donnent des noms parlants aux erreurs utilisees par l'application.
IntegrityError = ValueError
LockedError = PermissionError

# Taille fixe de l'en-tete : magic + version + sel + taille de l'index.
HEADER_SIZE = 4 + 1 + SALT_SIZE + 4
MAGIC = b"LBOX"
VERSION = b"\x01"
MAX_ATTEMPTS = 3
LOCK_DURATION = 60


def new_vault(vault_path: str, password: str) -> dict:
    """Prepare l'etat en memoire utilise par les autres fonctions."""
    return {"path": vault_path, "password": password, "index": {"files": {}},
            "salt": None, "key": None, "loaded": False}


def _password_key(vault: dict, salt: bytes) -> bytes:
    """Derive la cle qui protege l'index et la cle de donnees."""
    return derive_key(vault["password"], salt)


def _index_bytes(vault: dict, password_key: bytes) -> bytes:
    """Transforme l'index en JSON et y ajoute la cle de donnees enveloppee."""
    wrapped_key = encrypt_data(password_key, vault["key"]).hex()
    index = dict(vault["index"])
    index["wrapped_key"] = wrapped_key
    return json.dumps(index).encode("utf-8")


def _set_offsets(vault: dict, password_key: bytes) -> None:
    """Calcule la position de chaque blob apres l'index chiffre.

    L'index contient lui-meme les offsets, donc sa taille finale depend de ces
    valeurs. Deux passages suffisent ici pour stabiliser les positions.
    """
    for _ in range(2):
        test_index = encrypt_data(password_key, _index_bytes(vault, password_key))
        position = HEADER_SIZE + len(test_index)
        for info in vault["index"]["files"].values():
            info["offset"] = position
            position += info["size"]


def _write_vault(vault: dict, blobs: bytes) -> None:
    """Reecrit le vault avec son en-tete, son index chiffre et ses blobs."""
    password_key = _password_key(vault, vault["salt"])
    _set_offsets(vault, password_key)
    encrypted_index = encrypt_data(password_key, _index_bytes(vault, password_key))
    # Les blobs sont deja chiffres : ils doivent etre ecrits sans conversion.
    with open(vault["path"], "wb") as file:
        file.write(MAGIC + VERSION + vault["salt"])
        file.write(struct.pack("<I", len(encrypted_index)))
        file.write(encrypted_index)
        file.write(blobs)


def create_vault(vault: dict) -> None:
    """Cree un vault vide avec un sel et une cle de donnees aleatoires."""
    vault["salt"] = os.urandom(SALT_SIZE)
    vault["key"] = os.urandom(32)
    vault["index"] = {"files": {}}
    vault["loaded"] = True
    _write_vault(vault, b"")


def load_vault(vault: dict) -> None:
    """Charge et authentifie un vault existant.

    Le dechiffrement de l'index verifie le mot de passe. En cas d'echec, la
    tentative est enregistree dans le fichier de verrouillage.
    """
    if vault["loaded"]:
        return
    if is_locked(vault["path"]):
        remaining = int(locked_until(vault["path"]) - time.time())
        raise LockedError(f"Trop de tentatives. Reessayez dans {remaining} secondes.")
    if not os.path.exists(vault["path"]):
        raise FileNotFoundError("Vault non trouve.")

    try:
        with open(vault["path"], "rb") as file:
            magic = file.read(4)
            version = file.read(1)
            salt = file.read(SALT_SIZE)
            size_data = file.read(4)
            if magic != MAGIC or version != VERSION or len(salt) != SALT_SIZE:
                raise ValueError("Format de fichier inconnu.")
            if len(size_data) != 4:
                raise ValueError("Header incomplet.")
            # La taille est stockee sur 4 octets en little-endian.
            index_size = struct.unpack("<I", size_data)[0]
            encrypted_index = file.read(index_size)
            password_key = _password_key(vault, salt)
            index_data = decrypt_data(password_key, encrypted_index)
            index = json.loads(index_data.decode("utf-8"))
            wrapped_key = index.pop("wrapped_key", None)
            if not wrapped_key:
                raise ValueError("Cle du coffre absente.")
            vault["salt"] = salt
            vault["key"] = decrypt_data(password_key, bytes.fromhex(wrapped_key))
            vault["index"] = index
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        register_failed_attempt(vault["path"])
        raise IntegrityError("Mot de passe incorrect ou vault corrompu.")

    reset_bruteforce(vault["path"])
    vault["loaded"] = True


def _read_blobs(vault: dict) -> bytes:
    """Relit les blobs chiffres dans l'ordre indique par l'index."""
    blobs = bytearray()
    with open(vault["path"], "rb") as file:
        for info in vault["index"]["files"].values():
            file.seek(info["offset"])
            blobs.extend(file.read(info["size"]))
    return bytes(blobs)


def list_files(vault: dict) -> list[str]:
    """Retourne les noms des fichiers stockes dans le vault."""
    load_vault(vault)
    return list(vault["index"]["files"].keys())


def add_file(vault: dict, file_path: str) -> None:
    """Chiffre un fichier binaire et l'ajoute au vault."""
    if os.path.exists(vault["path"]):
        load_vault(vault)
        blobs = _read_blobs(vault)
    else:
        create_vault(vault)
        blobs = b""
    # rb/wb permettent de conserver exactement tous les octets du fichier.
    with open(file_path, "rb") as file:
        encrypted = encrypt_data(vault["key"], file.read())
    name = os.path.basename(file_path)
    vault["index"]["files"][name] = {"size": len(encrypted), "offset": 0}
    _write_vault(vault, blobs + encrypted)


def extract_file(vault: dict, filename: str, output_path: str) -> None:
    """Dechiffre un fichier du vault et l'ecrit a l'emplacement demande."""
    load_vault(vault)
    if filename not in vault["index"]["files"]:
        raise FileNotFoundError(f"Fichier '{filename}' non trouve.")
    info = vault["index"]["files"][filename]
    with open(vault["path"], "rb") as file:
        file.seek(info["offset"])
        encrypted = file.read(info["size"])
    try:
        data = decrypt_data(vault["key"], encrypted)
    except ValueError as error:
        raise IntegrityError(f"Le fichier '{filename}' est corrompu.") from error
    with open(output_path, "wb") as file:
        file.write(data)


def delete_file(vault: dict, filename: str) -> None:
    """Supprime un fichier puis reecrit les blobs restants."""
    load_vault(vault)
    if filename not in vault["index"]["files"]:
        raise FileNotFoundError(f"Fichier '{filename}' non trouve.")
    blobs = bytearray()
    with open(vault["path"], "rb") as file:
        for name, info in vault["index"]["files"].items():
            if name != filename:
                file.seek(info["offset"])
                blobs.extend(file.read(info["size"]))
    del vault["index"]["files"][filename]
    _write_vault(vault, bytes(blobs))


def change_password(vault: dict, new_password: str) -> None:
    """Remplace le mot de passe sans rechiffrer les fichiers.

    La cle de donnees reste la meme ; seul son emballage et le sel changent.
    """
    if not isinstance(new_password, str) or not new_password:
        raise ValueError("Le nouveau mot de passe est requis.")
    load_vault(vault)
    blobs = _read_blobs(vault)
    vault["password"] = new_password
    vault["salt"] = os.urandom(SALT_SIZE)
    _write_vault(vault, blobs)


def _lock_path(vault_path: str) -> str:
    """Retourne le chemin du fichier qui memorise les echecs de connexion."""
    return vault_path + ".lock"


def _load_lock_state(vault_path: str) -> dict:
    """Lit l'etat du verrou ou retourne un etat initial si absent/invalide."""
    try:
        with open(_lock_path(vault_path), "r") as file:
            attempts, locked_until_value = file.read().strip().split(",")
            return {"failed_attempts": int(attempts),
                    "locked_until": float(locked_until_value)}
    except (FileNotFoundError, ValueError):
        return {"failed_attempts": 0, "locked_until": 0.0}


def _save_lock_state(vault_path: str, state: dict) -> None:
    """Enregistre le compteur d'echecs et la date de fin du verrou."""
    with open(_lock_path(vault_path), "w") as file:
        file.write(f"{state['failed_attempts']},{state['locked_until']}")


def is_locked(vault_path: str) -> bool:
    """Indique si la date de fin du verrou est encore dans le futur."""
    return time.time() < _load_lock_state(vault_path)["locked_until"]


def locked_until(vault_path: str) -> float:
    """Retourne l'instant Unix jusqu'auquel le vault est verrouille."""
    return _load_lock_state(vault_path)["locked_until"]


def register_failed_attempt(vault_path: str) -> None:
    """Ajoute un echec et active le verrou apres le nombre maximal d'essais."""
    state = _load_lock_state(vault_path)
    state["failed_attempts"] += 1
    if state["failed_attempts"] >= MAX_ATTEMPTS:
        state["locked_until"] = time.time() + LOCK_DURATION
    _save_lock_state(vault_path, state)


def reset_bruteforce(vault_path: str) -> None:
    """Efface les echecs apres une authentification reussie."""
    _save_lock_state(vault_path, {"failed_attempts": 0, "locked_until": 0.0})
