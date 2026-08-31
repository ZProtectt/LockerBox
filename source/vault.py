import json
import os
import struct
import time

from source.crypto import derive_key, encrypt_data, decrypt_data
from cryptography.exceptions import InvalidTag


# ────────────────────────────────────────────────────────────────────────────
# Exceptions personnalisées
# ────────────────────────────────────────────────────────────────────────────
class IntegrityError(Exception):
    """
    Levée lorsque l'authentification AES-GCM échoue.
    
    Cela signifie soit que le mot de passe est incorrect (la clé dérivée ne
    correspond pas), soit que les données ont été altérées (tampering).
    
    Cette distinction intentionnelle sert à ne pas révéler à un attaquant
    si l'échec vient du mot de passe ou d'une corruption.
    """
    pass


class LockedError(Exception):
    """
    Levée lorsque le coffre est temporairement verrouillé par le système
    anti-bruteforce.
    
    Le verrouillage est déclenché après plusieurs tentatives infructueuses
    d'authentification et dure un temps prédéfini (LOCK_DURATION).
    """
    pass


# ────────────────────────────────────────────────────────────────────────────
# Format du fichier .vault (coffre)
# ────────────────────────────────────────────────────────────────────────────
# Le fichier vault a une structure binaire fixe :
#
# Octets  0‑3  : magic "LBOX" (4 octets) – signature d'identification
# Octet   4    : version 0x01 (1 octet) – permet d'évoluer le format
# Octets  5‑20 : sel Argon2 (16 octets) – unique par vault
# Octets 21‑24 : longueur de l'index chiffré (uint32 little-endian)
# Octets 25‑N  : index chiffré (nonce + ciphertext + tag AES‑GCM)
# Octets N‑fin : blobs des fichiers (chacun : nonce + ciphertext + tag)
#
# L'index est un objet JSON contenant la liste des fichiers et la wrapped_key
# (clé de données chiffrée avec la clé dérivée du mot de passe).
# Cette architecture permet de changer de mot de passe sans rechiffrer les
# fichiers : seule la wrapped_key est re-chiffrée.
HEADER_SIZE = 25  # 4 (magic) + 1 (version) + 16 (salt) + 4 (index_len)
MAGIC = b"LBOX"   # Signature au début du fichier
VERSION = b"\x01" # Version actuelle du format


class Vault:
    """
    Coffre-fort chiffré : gère la création, l'ouverture et les opérations sur fichiers.
    
    Ce coffre utilise un chiffrement hybride :
      1. Une clé de données aléatoire (32 octets) chiffre les fichiers.
      2. Cette clé est chiffrée (wrapped) avec une clé dérivée du mot de passe
         (via Argon2id) et stockée dans l'index.
      
    Avantages :
      - Changement de mot de passe sans re-chiffrer les fichiers.
      - Authentification forte via AES‑GCM (intégrité + confidentialité).
      - Protection contre la force brute via Argon2id et verrouillage temporaire.
    """
    
    # Paramètres anti-bruteforce
    MAX_ATTEMPTS = 3      # Nombre maximal de tentatives avant verrouillage
    LOCK_DURATION = 60    # Durée du verrouillage (secondes)

    def __init__(self, vault_path: str, password: str):
        """
        Initialise un objet Vault.
        
        Args:
            vault_path: Chemin vers le fichier .vault (ou à créer).
            password: Mot de passe maître pour dériver la clé.
            
        Note:
            La clé n'est pas dérivée immédiatement. L'initialisation est
            légère ; le vrai travail se fait lors de `load_vault()` ou
            `create_vault()`.
        """
        self.vault_path = vault_path
        self.lock_path = vault_path + ".lock"  # Fichier de verrouillage adjacent
        self.password = password
        
        # État du coffre (rempli par load_vault ou create_vault)
        self.index: dict = {"files": {}}  # Index des fichiers (nom → métadonnées)
        self.salt: bytes | None = None    # Sel Argon2 (unique par coffre)
        self.key: bytes | None = None     # Clé de données (aléatoire, chiffre les fichiers)
        
        # Mécanisme anti‑bruteforce persistant
        self.failed_attempts = 0          # Nombre d'échecs consécutifs
        self.locked_until = 0.0           # Timestamp de fin de verrouillage
        
        # Cache interne : indique si le coffre a déjà été chargé avec succès.
        # Évite de recharger l'index plusieurs fois pendant une même session CLI.
        self._loaded = False

    # ──────────────────────────────────────────────────────────────────────
    # Primitives bas niveau (méthodes internes)
    # ──────────────────────────────────────────────────────────────────────

    def _derive_password_key(self, salt: bytes) -> bytes:
        """
        Dérive la clé de mot de passe via Argon2id.
        
        Cette clé sert à chiffrer/déchiffrer la wrapped_key (clé de données).
        Elle n'est jamais utilisée directement pour chiffrer les fichiers.
        
        Args:
            salt: Sel de 16 octets (unique par coffre).
            
        Returns:
            Clé de 32 octets dérivée du mot de passe.
        """
        return derive_key(self.password, salt)

    def _build_index_payload(self, password_key: bytes) -> bytes:
        """
        Construit la sérialisation JSON de l'index, prête à être chiffrée.
        
        L'index contient :
          - La liste des fichiers avec leurs métadonnées (taille, offset)
          - La wrapped_key : la clé de données aléatoire chiffrée avec `password_key`
          
        Args:
            password_key: Clé dérivée du mot de passe (pour chiffrer la clé de données).
            
        Returns:
            Bytes de l'index JSON encodé en UTF‑8.
        """
        # Chiffre la clé de données avec la clé de mot de passe → wrapped_key
        wrapped_key = encrypt_data(password_key, self.key).hex()  # Stockage hexadécimal
        return json.dumps({
            **self.index,
            "wrapped_key": wrapped_key,
        }).encode()

    def _recompute_offsets(self, password_key: bytes) -> None:
        """
        Recalcule les offsets absolus de chaque fichier dans le coffre binaire.
        
        Problème circulaire : la taille de l'index chiffré dépend des offsets
        (car les offsets sont stockés dans l'index), mais les offsets dépendent
        de la taille de l'index (car les fichiers sont placés après l'index).
        
        Solution : deux passes suffisent pour converger car la variation de
        taille due aux offsets (entiers) est minime et bornée.
        
        Args:
            password_key: Clé de mot de passe (nécessaire pour chiffrer l'index
                          et connaître sa taille finale).
        """
        for _ in range(2):
            # Chiffre un index d'essai pour connaître sa taille
            sample_index = encrypt_data(password_key, self._build_index_payload(password_key))
            base = HEADER_SIZE + len(sample_index)  # Position après l'en-tête + index
            ptr = 0
            # Attribue à chaque fichier son offset (position dans le fichier)
            for info in self.index["files"].values():
                info["offset"] = base + ptr
                ptr += info["size"]

    def _read_file_blobs(self) -> bytes:
        """
        Lit tous les blobs chiffrés des fichiers, préservant leur ordre.
        
        Cette méthode est utilisée quand on modifie le coffre (ajout/suppression)
        pour récupérer les données existantes avant reconstruction.
        
        Returns:
            Concaténation de tous les blobs dans l'ordre de l'index.
        """
        blobs = bytearray()
        with open(self.vault_path, "rb") as f:
            for info in self.index["files"].values():
                f.seek(info["offset"])
                blobs.extend(f.read(info["size"]))
        return bytes(blobs)

    def _write_vault(self, blobs: bytes) -> None:
        """
        Écrit le coffre complet (en‑tête + index chiffré + blobs des fichiers).
        
        Cette méthode reconstruit entièrement le fichier .vault. Elle est
        appelée après chaque modification (ajout, suppression, changement de
        mot de passe).
        
        Args:
            blobs: Blobs chiffrés de tous les fichiers à écrire à la suite.
                   Doivent être dans le même ordre que `self.index["files"]`.
        """
        password_key = self._derive_password_key(self.salt)
        self._recompute_offsets(password_key)  # Met à jour les offsets
        encrypted_index = encrypt_data(password_key, self._build_index_payload(password_key))
        
        with open(self.vault_path, "wb") as f:
            # En‑tête fixe
            f.write(MAGIC + VERSION + self.salt)
            f.write(struct.pack("<I", len(encrypted_index)))  # Longueur de l'index
            # Index chiffré
            f.write(encrypted_index)
            # Données des fichiers
            f.write(blobs)

    # ──────────────────────────────────────────────────────────────────────
    # Opérations principales
    # ──────────────────────────────────────────────────────────────────────

    def create_vault(self) -> None:
        """
        Crée un nouveau coffre vide avec un sel aléatoire et une clé de données aléatoire.
        
        Cette méthode initialise toutes les structures internes et écrit le fichier
        vault sur le disque. Le coffre créé est immédiatement utilisable.
        
        Note:
            Le sel et la clé de données sont générés de manière cryptographiquement
            sûre via `os.urandom`. La clé de données est chiffrée avec la clé dérivée
            du mot de passe et stockée sous forme de wrapped_key dans l'index.
        """
        self.salt = os.urandom(16)          # Sel unique pour ce coffre
        self.key = os.urandom(32)           # Clé de données AES-256 aléatoire
        self.index = {"files": {}}          # Index vide
        self._loaded = True                  # Marque le coffre comme chargé
        self._write_vault(b"")               # Écrit le fichier avec zéro fichier

    def load_vault(self) -> None:
        """
        Charge et déchiffre l'index du coffre depuis le fichier.
        
        Cette méthode réalise plusieurs étapes :
          1. Vérifie si le coffre est déjà chargé en cache (_loaded).
          2. Vérifie l'existence du fichier vault.
          3. Vérifie le verrouillage anti-bruteforce.
          4. Lit l'en‑tête et extrait le sel.
          5. Déchiffre l'index avec la clé dérivée du mot de passe.
          6. Extrait la wrapped_key et déchiffre la clé de données.
          7. Réinitialise le compteur d'échecs après succès.
          
        En cas d'échec (mauvais mot de passe ou données corrompues), le système
        anti‑bruteforce enregistre une tentative infructueuse et lève `IntegrityError`.
        
        Raises:
            FileNotFoundError: Si le fichier vault n'existe pas.
            LockedError: Si le coffre est temporairement verrouillé.
            ValueError: Si le format du fichier est invalide.
            IntegrityError: Si le mot de passe est incorrect ou si les données
                            sont corrompues (échec de l'authentification AES‑GCM).
        """
        if self._loaded:
            return  # Déjà chargé (optimisation pour les opérations multiples)
        
        if not os.path.exists(self.vault_path):
            raise FileNotFoundError("Vault non trouvé.")

        # Vérification du verrouillage anti‑bruteforce avant toute tentative
        if self.is_locked():
            remaining = int(self.locked_until - time.time())
            raise LockedError(
                f"Trop de tentatives. Réessayez dans {remaining} secondes."
            )

        with open(self.vault_path, "rb") as f:
            # Lecture de l'en‑tête fixe
            magic = f.read(4)
            f.read(1)  # version (ignorée pour l'instant, réservée pour évolutions)
            self.salt = f.read(16)
            index_len = struct.unpack("<I", f.read(4))[0]

            if magic != MAGIC:
                raise ValueError("Format de fichier inconnu.")

            # Dérivation de la clé à partir du mot de passe et du sel
            password_key = self._derive_password_key(self.salt)
            
            try:
                # Déchiffrement de l'index
                encrypted_index = f.read(index_len)
                index_data = decrypt_data(password_key, encrypted_index)
                self.index = json.loads(index_data.decode())
                
                # Extraction de la wrapped_key (clé de données chiffrée)
                wrapped_key_hex = self.index.pop("wrapped_key", None)
                
                # Si une wrapped_key existe (nouveau format), on la déchiffre
                # Sinon, on utilise directement la clé de mot de passe (rétrocompatibilité)
                self.key = (
                    decrypt_data(password_key, bytes.fromhex(wrapped_key_hex))
                    if wrapped_key_hex
                    else password_key
                )
                
            except (InvalidTag, ValueError, json.JSONDecodeError):
                # Échec d'authentification → mauvaise clé ou données altérées
                self.register_failed_attempt()      # Incrémente le compteur d'échecs
                raise IntegrityError("Mot de passe incorrect ou vault corrompu.")

        # Authentification réussie : on réinitialise le mécanisme anti‑bruteforce
        self.reset_bruteforce()
        self._loaded = True

    def list_files(self) -> list[str]:
        """
        Retourne la liste des noms de fichiers stockés dans le coffre.
        
        Returns:
            Liste des noms de fichiers (sans chemin) présents dans le coffre.
            Retourne une liste vide si le coffre ne contient aucun fichier.
            
        Raises:
            LockedError: Si le coffre est temporairement verrouillé.
            IntegrityError: Si le mot de passe est incorrect.
            FileNotFoundError: Si le fichier vault n'existe pas.
        """
        self.load_vault()  # S'assure que le coffre est chargé et authentifié
        return list(self.index["files"].keys())

    def add_file(self, file_path: str) -> None:
        """
        Chiffre un fichier du système de fichiers et l'ajoute au coffre.
        
        Si le coffre n'existe pas encore, il est créé automatiquement.
        Si le coffre existe déjà, les blobs existants sont préservés et le
        nouveau fichier est ajouté à la fin.
        
        Args:
            file_path: Chemin absolu ou relatif vers le fichier à ajouter.
            
        Raises:
            FileNotFoundError: Si le fichier source n'existe pas.
            LockedError: Si le coffre est temporairement verrouillé.
            IntegrityError: Si le mot de passe est incorrect (pour un coffre existant).
            
        Note:
            Le nom du fichier dans le coffre est le nom de base du fichier source
            (sans le chemin). Deux fichiers avec le même nom ne peuvent pas coexister
            dans le coffre : le dernier ajouté écrase le précédent.
        """
        # Charge le coffre existant ou crée un nouveau si nécessaire
        if os.path.exists(self.vault_path):
            self.load_vault()
            blobs = self._read_file_blobs()  # Récupère tous les blobs existants
        else:
            self.create_vault()  # Crée un coffre vide
            blobs = b""

        # Lecture et chiffrement du fichier source
        with open(file_path, "rb") as f:
            plaintext = f.read()
        encrypted = encrypt_data(self.key, plaintext)  # Chiffrement AES‑GCM
        
        # Mise à jour de l'index avec les métadonnées du nouveau fichier
        name = os.path.basename(file_path)
        self.index["files"][name] = {"size": len(encrypted), "offset": 0}  # offset sera recalculé
        
        # Réécriture complète du coffre avec le nouveau blob ajouté à la fin
        self._write_vault(blobs + encrypted)

    def extract_file(self, filename: str, output_path: str) -> None:
        """
        Déchiffre un fichier du coffre et l'écrit sur le système de fichiers.
        
        Args:
            filename: Nom du fichier dans le coffre (tel que retourné par `list_files`).
            output_path: Chemin où écrire le fichier déchiffré.
            
        Raises:
            FileNotFoundError: Si le fichier n'existe pas dans le coffre.
            LockedError: Si le coffre est temporairement verrouillé.
            IntegrityError: Si le fichier est corrompu ou si l'authentification échoue.
        """
        self.load_vault()  # Authentification et chargement
        if filename not in self.index["files"]:
            raise FileNotFoundError(f"Fichier '{filename}' non trouvé.")

        # Lecture du blob chiffré depuis sa position dans le fichier vault
        info = self.index["files"][filename]
        with open(self.vault_path, "rb") as f:
            f.seek(info["offset"])
            encrypted = f.read(info["size"])

        # Déchiffrement avec vérification d'intégrité
        try:
            plaintext = decrypt_data(self.key, encrypted)
        except (InvalidTag, ValueError):
            raise IntegrityError(f"Le fichier '{filename}' est corrompu.")

        # Écriture du fichier déchiffré
        with open(output_path, "wb") as f:
            f.write(plaintext)

    def delete_file(self, filename: str) -> None:
        """
        Supprime un fichier du coffre sans rechiffrer les autres fichiers.
        
        Cette méthode réécrit entièrement le fichier vault en excluant le blob
        du fichier supprimé. Les offsets des fichiers restants sont recalculés.
        
        Args:
            filename: Nom du fichier à supprimer.
            
        Raises:
            FileNotFoundError: Si le fichier n'existe pas dans le coffre.
            LockedError: Si le coffre est temporairement verrouillé.
            IntegrityError: Si le mot de passe est incorrect.
        """
        self.load_vault()
        if filename not in self.index["files"]:
            raise FileNotFoundError(f"Fichier '{filename}' non trouvé.")

        # Lecture de tous les blobs SAUF celui du fichier à supprimer
        remaining_blobs = bytearray()
        with open(self.vault_path, "rb") as f:
            for name, info in self.index["files"].items():
                if name != filename:
                    f.seek(info["offset"])
                    remaining_blobs.extend(f.read(info["size"]))

        # Suppression de l'index et réécriture du coffre
        del self.index["files"][filename]
        self._write_vault(bytes(remaining_blobs))

    def change_password(self, new_password: str) -> None:
        """
        Change le mot de passe maître sans rechiffrer les fichiers.
        
        Cette opération est possible grâce à l'architecture à deux clés :
          - La clé de données (`self.key`) reste inchangée.
          - Seule la wrapped_key (enveloppe) est re-chiffrée avec la nouvelle
            clé dérivée du nouveau mot de passe.
          - Le sel est régénéré (bonne pratique cryptographique).
          
        Args:
            new_password: Nouveau mot de passe maître.
            
        Raises:
            ValueError: Si le nouveau mot de passe est vide ou invalide.
            LockedError: Si le coffre est temporairement verrouillé.
            IntegrityError: Si le mot de passe actuel est incorrect.
        """
        if not isinstance(new_password, str) or not new_password:
            raise ValueError("Le nouveau mot de passe est requis.")

        self.load_vault()  # Vérifie que le mot de passe actuel est correct
        blobs = self._read_file_blobs()  # Préservation des blobs existants

        # Mise à jour des informations d'authentification
        self.password = new_password
        self.salt = os.urandom(16)  # Nouveau sel (meilleure pratique)
        
        # Réécriture du coffre avec la nouvelle wrapped_key
        self._write_vault(blobs)

    # ──────────────────────────────────────────────────────────────────────
    # Protection anti-bruteforce (persistance via fichier .lock)
    # ──────────────────────────────────────────────────────────────────────

    def _load_lock_state(self):
        """
        Charge l'état anti‑bruteforce depuis le fichier `.lock`.
        
        Le fichier `.lock` contient deux valeurs séparées par une virgule :
          `failed_attempts,locked_until`
          
        Si le fichier n'existe pas ou est corrompu, l'état est réinitialisé à zéro.
        """
        try:
            with open(self.lock_path, "r") as f:
                data = f.read().strip().split(",")
                if len(data) == 2:
                    self.failed_attempts = int(data[0])
                    self.locked_until = float(data[1])
        except (FileNotFoundError, ValueError):
            # Fichier inexistant ou format invalide : on repart à zéro
            self.failed_attempts = 0
            self.locked_until = 0.0

    def _save_lock_state(self):
        """Sauvegarde l'état anti‑bruteforce dans le fichier `.lock`."""
        with open(self.lock_path, "w") as f:
            f.write(f"{self.failed_attempts},{self.locked_until}")

    def is_locked(self) -> bool:
        """
        Vérifie si le coffre est actuellement verrouillé.
        
        Returns:
            True si le temps actuel est inférieur à `locked_until`,
            False sinon (coffre accessible).
        """
        self._load_lock_state()
        return time.time() < self.locked_until

    def register_failed_attempt(self) -> None:
        """
        Enregistre une tentative d'authentification infructueuse.
        
        Cette méthode incrémente le compteur d'échecs. Si le nombre maximal
        d'essais (`MAX_ATTEMPTS`) est atteint, le coffre est verrouillé pour
        une durée définie par `LOCK_DURATION`.
        
        L'état est immédiatement sauvegardé dans le fichier `.lock`.
        """
        self._load_lock_state()
        self.failed_attempts += 1
        if self.failed_attempts >= self.MAX_ATTEMPTS:
            self.locked_until = time.time() + self.LOCK_DURATION
        self._save_lock_state()

    def reset_bruteforce(self) -> None:
        """
        Réinitialise le mécanisme anti‑bruteforce après une authentification réussie.
        
        Cette méthode est appelée par `load_vault()` quand le mot de passe est
        correct. Elle remet à zéro le compteur d'échecs et efface le verrouillage.
        """
        self.failed_attempts = 0
        self.locked_until = 0.0
        self._save_lock_state()
