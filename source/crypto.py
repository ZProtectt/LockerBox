import os

from argon2.low_level import hash_secret_raw, Type
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ────────────────────────────────────────────────────────────────────────────
# Constantes cryptographiques
# ────────────────────────────────────────────────────────────────────────────
NONCE_SIZE = 12          # Taille du nonce pour AES-GCM (recommandée par NIST)
SALT_SIZE = 16           # Sel de 128 bits pour Argon2


def derive_key(password: str, salt: bytes, key_length: int = 32) -> bytes:
    """
    Dérive une clé AES-256 depuis un mot de passe via Argon2id.
    
    Argon2id est un algorithme de hachage de mot de passe moderne résistant
    aux attaques par force brute et par canal auxiliaire (side-channel).
    
    Paramètres choisis pour un bon équilibre sécurité/performance :
      - time_cost=3       : 3 itérations
      - memory_cost=65536 : 64 MiB de mémoire (décourage le matériel spécialisé)
      - parallelism=4     : 4 threads (utilise plusieurs cœurs CPU)
      
    Args:
        password: Mot de passe en clair.
        salt: Sel de 16 octets (aléatoire, unique par vault).
        key_length: Longueur de clé souhaitée (32 octets pour AES-256).
        
    Returns:
        Clé dérivée de `key_length` octets.
        
    Raises:
        TypeError: Si `password` n'est pas une chaîne.
        ValueError: Si `salt` n'a pas la taille attendue.
    """
    if not isinstance(password, str):
        raise TypeError("Le mot de passe doit être une chaîne.")
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != SALT_SIZE:
        raise ValueError("Le sel doit faire 16 octets.")
    if key_length != 32:
        raise ValueError("Seule une clé de 32 octets (AES-256) est supportée.")
    
    # Appel à la bibliothèque argon2-cffi (implémentation optimisée en C)
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=bytes(salt),
        time_cost=3,
        memory_cost=65536,      # 64 MiB
        parallelism=4,
        hash_len=key_length,
        type=Type.ID,           # Argon2id (hybride)
    )


def encrypt_data(key: bytes, data: bytes) -> bytes:
    """
    Chiffre des données avec AES-256-GCM (Galois/Counter Mode).
    
    AES-GCM fournit à la fois confidentialité et authentification (intégrité).
    Le tag d'authentification est inclus automatiquement avec le ciphertext.
    
    Format de sortie :
        [nonce (12 octets)][ciphertext][tag (16 octets)]
        
    Le nonce (number used once) est aléatoire et doit être unique pour chaque
    chiffrement avec la même clé. Il n'a pas besoin d'être secret.
    
    Args:
        key: Clé AES-256 de 32 octets.
        data: Données en clair à chiffrer.
        
    Returns:
        Payload chiffré (nonce + ciphertext + tag).
        
    Raises:
        ValueError: Si la clé n'a pas la taille attendue.
    """
    if len(key) != 32:
        raise ValueError("La clé doit faire 32 octets pour AES-256.")
    
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)          # Nonce aléatoire de 12 octets
    ciphertext = aesgcm.encrypt(nonce, data, None)  # `None` = pas de données associées
    return nonce + ciphertext               # Format compact pour stockage


def decrypt_data(key: bytes, payload: bytes) -> bytes:
    """
    Déchiffre un payload AES-256-GCM et vérifie son authenticité.
    
    Vérifie d'abord que le payload a une taille minimale, puis tente le
    déchiffrement. Si le tag d'authentification est invalide (mauvaise clé
    ou données altérées), une exception est levée.
    
    Args:
        key: Clé AES-256 de 32 octets.
        payload: Données chiffrées (nonce + ciphertext + tag).
        
    Returns:
        Données en clair originales.
        
    Raises:
        ValueError: Si le payload est trop court ou si le tag est invalide
                    (tentative d'altération détectée).
    """
    # Vérification de base : le payload doit contenir au moins le nonce + tag
    if len(payload) < NONCE_SIZE + 16:
        raise ValueError("Tampering détecté : payload trop court.")
    
    aesgcm = AESGCM(key)
    nonce = payload[:NONCE_SIZE]           # Extraire le nonce
    ciphertext = payload[NONCE_SIZE:]      # Reste = ciphertext + tag
    
    try:
        return aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        # Le tag AES-GCM est invalide → données corrompues ou mauvaise clé
        raise ValueError("Tampering détecté.") from exc
