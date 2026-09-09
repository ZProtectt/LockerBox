import hashlib
import json
import os
import struct
import time

from source.crypto import SALT_SIZE, decrypt_data, derive_key, encrypt_data

# Ces alias donnent des noms parlants aux erreurs pour mieux comprendre leur signification.
IntegrityError = ValueError
LockedError = PermissionError

# Taille de l'en-tete : magic + version + sel + taille de l'index.
HEADER_SIZE = 4 + 1 + SALT_SIZE + 4
MAGIC = b"LBOX"
VERSION = b"\x01"
MAX_ATTEMPTS = 3
LOCK_DURATION = 60


def new_vault(vault_path: str, password: str) -> dict:
    # Crée un dictionnaire vide contenant le chemin, le mot de passe, un index vide, et des valeurs initiales pour le sel et la clé.
    return {"path": vault_path, "password": password, "index": {"files": {}},
            "salt": None, "key": None, "loaded": False}


def _password_key(vault: dict, salt: bytes) -> bytes:
    # Derive une clé à partir du mot de passe maître et du sel.
    return derive_key(vault["password"], salt)


def _index_bytes(vault: dict, password_key: bytes) -> bytes:
    # Transforme l'index et y ajoute la clé de données chiffrée.
    wrapped_key = encrypt_data(password_key, vault["key"]).hex()
    index = dict(vault["index"])
    index["wrapped_key"] = wrapped_key

    # On convertit l'index en JSON et on l'encode en UTF-8 pour obtenir une représentation binaire.
    return json.dumps(index).encode("utf-8")


def _set_offsets(vault: dict, password_key: bytes) -> None:
    # Calcule les offsets des fichiers dans le vault en fonction de la taille de l'index chiffré.
    for _ in range(2):
        test_index = encrypt_data(password_key, _index_bytes(vault, password_key))
        position = HEADER_SIZE + len(test_index)
        for info in vault["index"]["files"].values():
            info["offset"] = position
            position += info["size"]


def _write_vault(vault: dict, blobs: bytes) -> None:
    # Ecrit le vault sur le disque avec l'en-tete, l'index chiffré et les blobs de fichiers.
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
    # Crée un nouveau vault vide avec un sel et une clé de données aléatoires.
    vault["salt"] = os.urandom(SALT_SIZE)
    vault["key"] = os.urandom(32)
    vault["index"] = {"files": {}}
    vault["loaded"] = True
    _write_vault(vault, b"")


def load_vault(vault: dict) -> None:
    # Charge le vault depuis le disque, déchiffre l'index et la clé de données, et vérifie l'intégrité.
    if vault["loaded"]:
        return
    if is_locked(vault["path"]):
        remaining = int(locked_until(vault["path"]) - time.time())
        raise LockedError(f"Trop de tentatives. Reessayez dans {remaining} secondes.")
    if not os.path.exists(vault["path"]):
        raise FileNotFoundError("Vault non trouve.")

    # On lit l'en-tete du vault pour obtenir le sel et la taille de l'index chiffré.
    try:
        with open(vault["path"], "rb") as file:
            # On lit le magic, la version, le sel et la taille de l'index.
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

            # On déchiffre l'index et on le convertit en dictionnaire Python.
            index_data = decrypt_data(password_key, encrypted_index)
            index = json.loads(index_data.decode("utf-8"))
            wrapped_key = index.pop("wrapped_key", None)

            if not wrapped_key:
                raise ValueError("Cle du coffre absente.")
            
            # On déchiffre la clé de données avec la clé dérivée du mot de passe.
            vault["salt"] = salt
            vault["key"] = decrypt_data(password_key, bytes.fromhex(wrapped_key))
            vault["index"] = index
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        register_failed_attempt(vault["path"])
        raise IntegrityError("Mot de passe incorrect ou vault corrompu.")

    # Si tout s'est bien passé, on réinitialise le compteur d'échecs et on marque le vault comme chargé.
    reset_bruteforce(vault["path"])
    vault["loaded"] = True


def _read_blobs(vault: dict) -> bytes:
    # Lit les blobs de fichiers du vault en utilisant les offsets et tailles stockés dans l'index.
    blobs = bytearray()
    with open(vault["path"], "rb") as file:
        # On parcourt les fichiers dans l'index et on lit leurs blobs en utilisant les offsets et tailles stockés.
        for info in vault["index"]["files"].values():
            file.seek(info["offset"])
            blobs.extend(file.read(info["size"]))
    return bytes(blobs)


def list_files(vault: dict) -> list[str]:
    # Charge le vault si ce n'est pas deja fait et retourne la liste des fichiers.
    load_vault(vault)
    return list(vault["index"]["files"].keys())


def add_file(vault: dict, file_path: str) -> None:
    # Charge le vault si ce n'est pas deja fait, lit le fichier source, le chiffre et l'ajoute au vault.

    # On vérifie si le fichier source existe avant de continuer.
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

    # On écrit le vault avec les blobs existants plus le nouveau fichier chiffré.
    _write_vault(vault, blobs + encrypted)


def extract_file(vault: dict, filename: str, output_path: str) -> None:
    # Charge le vault si ce n'est pas deja fait, lit le fichier chiffre, le dechiffre et l'ecrit sur le disque.
    load_vault(vault)
    if filename not in vault["index"]["files"]:
        raise FileNotFoundError(f"Fichier '{filename}' non trouve.")

    # On lit le fichier chiffré depuis le vault en utilisant l'offset et la taille stockés dans l'index.
    info = vault["index"]["files"][filename]

    # On lit le fichier chiffré depuis le vault en utilisant l'offset et la taille stockés dans l'index.
    with open(vault["path"], "rb") as file:
        file.seek(info["offset"])
        encrypted = file.read(info["size"])
    try:
        # On déchiffre les données avec la clé de données du vault. Si le tag est invalide, on lève une IntegrityError.
        data = decrypt_data(vault["key"], encrypted)
    except ValueError as error:
        raise IntegrityError(f"Le fichier '{filename}' est corrompu.") from error
    with open(output_path, "wb") as file:
        file.write(data)


def delete_file(vault: dict, filename: str) -> None:
    # Charge le vault si ce n'est pas deja fait, lit tous les blobs sauf celui a supprimer, met a jour l'index et ecrit le vault.
    load_vault(vault)

    if filename not in vault["index"]["files"]:
        raise FileNotFoundError(f"Fichier '{filename}' non trouve.")

    blobs = bytearray()
    # On lit tous les fichiers sauf celui à supprimer et on les stocke dans un tableau de bytes.
    with open(vault["path"], "rb") as file:
        for name, info in vault["index"]["files"].items():
            if name != filename:
                file.seek(info["offset"])
                blobs.extend(file.read(info["size"]))
    del vault["index"]["files"][filename]
    _write_vault(vault, bytes(blobs))


def change_password(vault: dict, new_password: str) -> None:
    # Le nouveau mot de passe doit etre une chaine non vide.
    if not isinstance(new_password, str) or not new_password:
        raise ValueError("Le nouveau mot de passe est requis.")
    load_vault(vault)

    # On lit tous les blobs existants pour les réécrire avec le nouveau mot de passe.
    blobs = _read_blobs(vault)

    # On met à jour le mot de passe et le sel, puis on réécrit le vault avec les blobs existants.
    vault["password"] = new_password
    vault["salt"] = os.urandom(SALT_SIZE)
    _write_vault(vault, blobs)


def _lock_path(vault_path: str) -> str:
    # Retourne le chemin du fichier de verrouillage associé au vault.
    lock_root = os.getenv("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), ".lockerbox")
    vault_id = hashlib.sha256(os.path.abspath(vault_path).encode("utf-8")).hexdigest()
    return os.path.join(lock_root, "LockerBox", "locks", f"{vault_id}.lock")


def _load_lock_state(vault_path: str) -> dict:
    # Lit l'etat du verrou ou retourne un etat initial si absent/invalide.
    try:
        with open(_lock_path(vault_path), "r") as file:
            attempts, locked_until_value = file.read().strip().split(",")

            # On convertit les valeurs en types appropriés et on retourne un dictionnaire représentant l'état du verrou.
            return {"failed_attempts": int(attempts),
                    "locked_until": float(locked_until_value)}
    except (FileNotFoundError, ValueError):
        return {"failed_attempts": 0, "locked_until": 0.0}


def _save_lock_state(vault_path: str, state: dict) -> None:
    # Enregistre le compteur d'echecs et la date de fin du verrou.
    lock_path = _lock_path(vault_path)
    os.makedirs(os.path.dirname(lock_path), exist_ok=True)
    with open(lock_path, "w") as file:
        file.write(f"{state['failed_attempts']},{state['locked_until']}")


def is_locked(vault_path: str) -> bool:
    # Indique si la date de fin du verrou est encore dans le futur.
    return time.time() < _load_lock_state(vault_path)["locked_until"]


def locked_until(vault_path: str) -> float:
    # Retourne l'instant Unix jusqu'auquel le vault est verrouille, ou 0 si le vault n'est pas verrouille.
    return _load_lock_state(vault_path)["locked_until"]


def register_failed_attempt(vault_path: str) -> None:
    # Ajoute un echec et active le verrou apres le nombre maximal d'essais.
    state = _load_lock_state(vault_path)
    state["failed_attempts"] += 1

    # Si le nombre d'échecs atteint le maximum, on verrouille le vault pour une durée définie.
    if state["failed_attempts"] >= MAX_ATTEMPTS:
        state["locked_until"] = time.time() + LOCK_DURATION
    _save_lock_state(vault_path, state)


def reset_bruteforce(vault_path: str) -> None:
    # Efface le compteur d'echecs et la date de fin du verrou apres une authentification reussie.
    _save_lock_state(vault_path, {"failed_attempts": 0, "locked_until": 0.0})
