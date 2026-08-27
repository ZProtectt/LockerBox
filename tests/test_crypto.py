import os
import tempfile

import pytest

from source.crypto import derive_key, decrypt_data, encrypt_data
from source.vault import IntegrityError, Vault


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

        v = Vault(vault_path, "motdepasse")
        v.create_vault()
        v.add_file(src)
        v.extract_file("secret.txt", out)
        assert open(out, "rb").read() == b"contenu secret"


def test_vault_wrong_password():
    """Ouvrir avec un mauvais mot de passe doit lever IntegrityError."""
    with tempfile.TemporaryDirectory() as d:
        vault_path = os.path.join(d, "test.lbox")
        Vault(vault_path, "bon").create_vault()
        with pytest.raises(IntegrityError):
            Vault(vault_path, "mauvais").load_vault()


def test_vault_delete_file():
    """Supprimer un fichier ne doit pas corrompre les autres."""
    with tempfile.TemporaryDirectory() as d:
        vault_path = os.path.join(d, "test.lbox")
        f1 = os.path.join(d, "a.txt")
        f2 = os.path.join(d, "b.txt")
        out = os.path.join(d, "out.txt")
        open(f1, "wb").write(b"aaa")
        open(f2, "wb").write(b"bbb")

        v = Vault(vault_path, "mdp")
        v.create_vault()
        v.add_file(f1)
        v.add_file(f2)
        v.delete_file("a.txt")
        assert v.list_files() == ["b.txt"]
        v.extract_file("b.txt", out)
        assert open(out, "rb").read() == b"bbb"


def test_vault_change_password():
    """Changer le mot de passe doit permettre de rouvrir le vault."""
    with tempfile.TemporaryDirectory() as d:
        vault_path = os.path.join(d, "test.lbox")
        src = os.path.join(d, "secret.txt")
        out = os.path.join(d, "out.txt")
        open(src, "wb").write(b"donnee")

        v = Vault(vault_path, "ancien")
        v.create_vault()
        v.add_file(src)
        v.change_password("nouveau")

        with pytest.raises(IntegrityError):
            Vault(vault_path, "ancien").load_vault()

        v2 = Vault(vault_path, "nouveau")
        v2.extract_file("secret.txt", out)
        assert open(out, "rb").read() == b"donnee"


def test_vault_bruteforce_lock():
    """Après 3 échecs, is_locked() doit retourner True."""
    with tempfile.TemporaryDirectory() as d:
        v = Vault(os.path.join(d, "v.lbox"), "mdp")
        for _ in range(3):
            v.register_failed_attempt()
        assert v.is_locked()
