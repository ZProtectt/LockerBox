
import os
import tempfile

import pytest

from source.crypto import derive_key, decrypt_data, encrypt_data
from source.vault import (
    IntegrityError,
    LockedError,
    add_file,
    change_password,
    create_vault,
    delete_file,
    extract_file,
    is_locked,
    list_files,
    load_vault,
    new_vault,
    register_failed_attempt,
)


# ── Tests crypto ──────────────────────────────────────────────────────────

def test_encryption_roundtrip():
    """Chiffrer puis déchiffrer redonne les données initiales."""
    key = derive_key("MotDePasse!", os.urandom(16))
    data = b"Message confidentiel."
    assert decrypt_data(key, encrypt_data(key, data)) == data


def test_tampering_detection():
    """Modifier un octet du payload doit lever ValueError."""
    key = derive_key("AutreMotDePasse", os.urandom(16))
    payload = bytearray(encrypt_data(key, b"Donnees sensibles."))
    payload[-1] ^= 0x01
    with pytest.raises(ValueError):
        decrypt_data(key, bytes(payload))


def test_wrong_key_raises():
    """Déchiffrer avec une mauvaise clé doit lever ValueError."""
    key1 = derive_key("cle1", os.urandom(16))
    key2 = derive_key("cle2", os.urandom(16))
    payload = encrypt_data(key1, b"secret")
    with pytest.raises(ValueError):
        decrypt_data(key2, payload)


# ── Tests vault ───────────────────────────────────────────────────────────

def test_vault_add_and_extract():
    """Ajouter un fichier puis l'extraire redonne le contenu original."""
    with tempfile.TemporaryDirectory() as d:
        vault_path = os.path.join(d, "test.lbox")
        src = os.path.join(d, "secret.txt")
        out = os.path.join(d, "output.txt")
        open(src, "wb").write(b"contenu secret")

        v = new_vault(vault_path, "motdepasse")
        create_vault(v)
        add_file(v, src)
        extract_file(v, "secret.txt", out)
        assert open(out, "rb").read() == b"contenu secret"


def test_vault_binary_file_roundtrip():
    """Un fichier binaire est conserve octet par octet."""
    with tempfile.TemporaryDirectory() as d:
        vault_path = os.path.join(d, "binary.lbox")
        src = os.path.join(d, "image.bin")
        out = os.path.join(d, "restored.bin")
        data = bytes(range(256)) + b"\x00\xff\x00"
        with open(src, "wb") as file:
            file.write(data)

        vault = new_vault(vault_path, "motdepasse")
        create_vault(vault)
        add_file(vault, src)
        extract_file(vault, "image.bin", out)

        with open(out, "rb") as file:
            assert file.read() == data


def test_vault_wrong_password():
    """Ouvrir avec un mauvais mot de passe doit lever IntegrityError."""
    with tempfile.TemporaryDirectory() as d:
        vault_path = os.path.join(d, "test.lbox")
        create_vault(new_vault(vault_path, "bon"))
        with pytest.raises(IntegrityError):
            load_vault(new_vault(vault_path, "mauvais"))


def test_vault_delete_file():
    """Supprimer un fichier ne doit pas corrompre les autres."""
    with tempfile.TemporaryDirectory() as d:
        vault_path = os.path.join(d, "test.lbox")
        f1 = os.path.join(d, "a.txt")
        f2 = os.path.join(d, "b.txt")
        out = os.path.join(d, "out.txt")
        open(f1, "wb").write(b"aaa")
        open(f2, "wb").write(b"bbb")

        v = new_vault(vault_path, "mdp")
        create_vault(v)
        add_file(v, f1)
        add_file(v, f2)
        delete_file(v, "a.txt")
        assert list_files(v) == ["b.txt"]
        extract_file(v, "b.txt", out)
        assert open(out, "rb").read() == b"bbb"


def test_vault_change_password():
    """Changer le mot de passe doit permettre de rouvrir le vault."""
    with tempfile.TemporaryDirectory() as d:
        vault_path = os.path.join(d, "test.lbox")
        src = os.path.join(d, "secret.txt")
        out = os.path.join(d, "out.txt")
        open(src, "wb").write(b"donnee")

        v = new_vault(vault_path, "ancien")
        create_vault(v)
        add_file(v, src)
        change_password(v, "nouveau")

        with pytest.raises(IntegrityError):
            load_vault(new_vault(vault_path, "ancien"))

        v2 = new_vault(vault_path, "nouveau")
        extract_file(v2, "secret.txt", out)
        assert open(out, "rb").read() == b"donnee"


def test_vault_bruteforce_lock():
    """Après 3 échecs, is_locked() doit retourner True même sur une nouvelle instance."""
    with tempfile.TemporaryDirectory() as d:
        vault_path = os.path.join(d, "v.lbox")

        # 3 échecs sur une première instance
        v1 = new_vault(vault_path, "mdp")
        for _ in range(3):
            register_failed_attempt(vault_path)
        assert is_locked(vault_path)

        # Une nouvelle instance doit aussi voir le verrou (persistance .lock)
        v2 = new_vault(vault_path, "mdp")
        assert is_locked(vault_path)

        # load_vault() doit lever LockedError
        with pytest.raises(LockedError):
            load_vault(v2)
