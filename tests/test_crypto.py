
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

def test_vault_tampering_detected_on_open():
    # Test pour vérifier que la modification de l'index du vault est détectée lors de son ouverture.
    with tempfile.TemporaryDirectory() as d:
        vault_path = os.path.join(d, "tampered.lbox")
        create_vault(new_vault(vault_path, "motdepasse"))

        with open(vault_path, "rb") as file:
            tampered_vault = bytearray(file.read())

        index_size = int.from_bytes(tampered_vault[21:25], "little")
        tampered_vault[25 + index_size - 1] ^= 0x01

        with open(vault_path, "wb") as file:
            file.write(tampered_vault)

        with pytest.raises(IntegrityError, match="Mot de passe incorrect ou vault corrompu") as error_info:
            load_vault(new_vault(vault_path, "motdepasse"))
        print("Erreur détectée à l'ouverture :", error_info.value)