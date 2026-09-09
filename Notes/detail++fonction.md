Parfait ! Maintenant je vais analyser en détail chaque fonction du fichier `vault.py`. Je vais structurer l'explication par blocs fonctionnels.

---

# **ANALYSE DÉTAILLÉE DU FICHIER VAULT.PY**

## **1. CONSTANTES ET ALIAS (Lignes 1-19)**

```python
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
```

**Explications :**
- **`IntegrityError = ValueError`** : Crée un alias pour les erreurs d'intégrité (plus parlant)
- **`LockedError = PermissionError`** : Alias pour erreurs de verrouillage
- **`HEADER_SIZE`** : Calculée dynamiquement (4 magic + 1 version + 16 salt + 4 taille index = 25 octets)
- **`MAGIC = b"LBOX"`** : Signature identifiant le format
- **`VERSION = b"\x01"`** : Version 1, extensible pour futures versions
- **`MAX_ATTEMPTS = 3`** : Politique anti brute-force
- **`LOCK_DURATION = 60`** : 60 secondes de verrouillage après 3 échecs

---

## **2. STRUCTURE DE DONNÉES EN MÉMOIRE**

### **`new_vault(vault_path, password)` (Lignes 21-24)**
```python
def new_vault(vault_path: str, password: str) -> dict:
    # Crée un dictionnaire vide contenant le chemin, le mot de passe, un index vide, 
    # et des valeurs initiales pour le sel et la clé.
    return {"path": vault_path, "password": password, "index": {"files": {}},
            "salt": None, "key": None, "loaded": False}
```

**Détails :**
- **Retourne un dictionnaire** représentant l'état d'un vault en mémoire
- **Structure du dict** :
  - `"path"` : Chemin du fichier .vault sur disque
  - `"password"` : Mot de passe utilisateur (stocké en mémoire uniquement)
  - `"index"` : Métadonnées fichiers (`{"files": {...}}`)
  - `"salt"` : `None` initialement, défini lors de `create_vault()`
  - `"key"` : `None` initialement, défini lors de `create_vault()` (clé de données)
  - `"loaded"` : `False` → pas encore ouvert/déchiffré
- **Important** : Ce dict est l'objet principal manipulé par toutes les fonctions

---

## **3. FONCTIONS INTERNES DE SUPPORT**

### **`_password_key(vault, salt)` (Lignes 27-29)**
```python
def _password_key(vault: dict, salt: bytes) -> bytes:
    # Derive une clé à partir du mot de passe maître et du sel.
    return derive_key(vault["password"], salt)
```

**Rôle :** Couche d'abstraction qui appelle `derive_key()` du module crypto  
**Pourquoi ?** : Centraliser l'appel, futur changement possible  
**Entrée** : Vault dict + sel (16 octets)  
**Sortie** : Clé de 32 octets dérivée du mot de passe  

---

### **`_index_bytes(vault, password_key)` (Lignes 32-39)**
```python
def _index_bytes(vault: dict, password_key: bytes) -> bytes:
    # Transforme l'index et y ajoute la clé de données chiffrée.
    wrapped_key = encrypt_data(password_key, vault["key"]).hex()
    index = dict(vault["index"])
    index["wrapped_key"] = wrapped_key

    # On convertit l'index en JSON et on l'encode en UTF-8 pour obtenir une représentation binaire.
    return json.dumps(index).encode("utf-8")
```

**Processus détaillé :**
1. **`encrypt_data(password_key, vault["key"])`** : Chiffre la `data_key` avec la `password_key`
2. **`.hex()`** : Convertit en représentation hexadécimale (texte JSON-compatible)
3. **`dict(vault["index"])`** : Crée copie de l'index (évite modifications accidentelles)
4. **`index["wrapped_key"] = wrapped_key`** : Ajoute la clé chiffrée à l'index
5. **`json.dumps(index).encode("utf-8")`** : Sérialise en JSON → bytes

**Résultat exemple :**
```json
{
  "files": {
    "document.pdf": {"offset": 1024, "size": 5000},
    "photo.jpg": {"offset": 6024, "size": ●●●}
  },
  "wrapped_key": "a1b2c3d4e5f6..."  // 32 octets chiffrés en hex
}
```

---

### **`_set_offsets(vault, password_key)` (Lignes 42-50)**
```python
def _set_offsets(vault: dict, password_key: bytes) -> None:
    # Calcule les offsets des fichiers dans le vault en fonction de la taille de l'index chiffré.
    for _ in range(2):
        test_index = encrypt_data(password_key, _index_bytes(vault, password_key))
        position = HEADER_SIZE + len(test_index)
        for info in vault["index"]["files"].values():
            info["offset"] = position
            position += info["size"]
```

**Problème à résoudre :** Calculer où chaque fichier commence dans le vault

**Détails :**
1. **Boucle `for _ in range(2)`** : Pourquoi 2 itérations ?
   - **Itération 1** : Calcule taille index avec offsets par défaut
   - **Itération 2** : Recalcule avec vrais offsets (plus précis)
   - Garantit précision car taille index change avec offsets

2. **`test_index = encrypt_data(...)`** : Simule chiffrement index pour connaître sa taille réelle

3. **`position = HEADER_SIZE + len(test_index)`** :
   - `HEADER_SIZE` = 25 octets
   - `len(test_index)` = index chiffré (nonce + données + tag)
   - Position de départ du premier fichier

4. **Boucle sur fichiers** : Attribue offset à chaque fichier
   ```
   Fichier 1 → offset = HEADER_SIZE + taille_index
   Fichier 2 → offset = précédent + taille_fichier1
   Fichier 3 → offset = précédent + taille_fichier2
   ```

---

### **`_read_blobs(vault)` (Lignes 125-134 environ)**
```python
def _read_blobs(vault: dict) -> bytes:
    # Lit les blobs de fichiers du vault en utilisant les offsets et tailles stockés dans l'index.
    blobs = bytearray()
    with open(vault["path"], "rb") as file:
        # On parcourt les fichiers dans l'index et on lit leurs blobs en utilisant les offsets et tailles stockés.
        for info in vault["index"]["files"].values():
            file.seek(info["offset"])
            blobs.extend(file.read(info["size"]))
    return bytes(blobs)
```

**Rôle critique :** Lit TOUS les fichiers chiffrés du vault pour reconstruction

**Processus :**
1. **`bytearray()`** : Buffer mutable efficace pour accumulation
2. **`open(vault["path"], "rb")`** : Ouvre vault en mode binaire (lecture octets)
3. **Pour chaque fichier dans index** :
   - **`file.seek(info["offset"])`** : Saute directement à la position
   - **`file.read(info["size"])`** : Lit exactement la taille connue
   - **`blobs.extend(...)`** : Ajoute au buffer
4. **`return bytes(blobs)`** : Convertit en bytes immuable

**Usage dans :**
- `change_password()` : Lit tout pour réécrire avec nouveau mot de passe
- `add_file()` : Lit tout pour ajouter nouveau fichier
- `delete_file()` : Lit tout SAUF fichier supprimé

**Performance :** O(n) où n = taille totale fichiers, nécessite tout charger en RAM

---

### **`_write_vault(vault, blobs)` (Lignes 52-64)**
```python
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
```

**La fonction la plus importante** : Construit le fichier .vault final

**Étapes :**
1. **`password_key = _password_key(...)`** : Dérive clé depuis mot de passe + sel
2. **`_set_offsets(...)`** : Calcule positions fichiers
3. **`encrypted_index = encrypt_data(...)`** : Chiffre l'index complet

**Écriture fichier :**
```
file.write(MAGIC + VERSION + vault["salt"])        # Header (21 octets)
file.write(struct.pack("<I", len(encrypted_index))) # Taille index (4 octets)
file.write(encrypted_index)                        # Index chiffré
file.write(blobs)                                  # Fichiers chiffrés
```

**`struct.pack("<I", ...)`** : Encode entier 32 bits little-endian (standard Windows)

---

## **4. FONCTIONS PRINCIPALES D'OPÉRATION**

### **`create_vault(vault)` (Lignes 66-72)**
```python
def create_vault(vault: dict) -> None:
    # Crée un nouveau vault vide avec un sel et une clé de données aléatoires.
    vault["salt"] = os.urandom(SALT_SIZE)
    vault["key"] = os.urandom(32)
    vault["index"] = {"files": {}}
    vault["loaded"] = True
    _write_vault(vault, b"")
```

**Initialisation complète :**
1. **`vault["salt"] = os.urandom(SALT_SIZE)`** : Génère sel aléatoire (16 octets)
2. **`vault["key"] = os.urandom(32)`** : Génère clé de données aléatoire (32 octets)
3. **`vault["index"] = {"files": {}}`** : Index vide
4. **`vault["loaded"] = True`** : Marqué comme chargé (pas besoin `load_vault()`)
5. **`_write_vault(vault, b"")`** : Écrit vault vide (pas de fichiers)

**Points clés :**
- `os.urandom()` : Cryptographiquement sécurisé
- Vault créé est **immédiatement utilisable** (`loaded=True`)

---

### **`load_vault(vault)` (Lignes 75-124)**
```python
def load_vault(vault: dict) -> None:
    # Charge le vault depuis le disque, déchiffre l'index et la clé de données, et vérifie l'intégrité.
    if vault["loaded"]:
        return
    if is_locked(vault["path"]):
        remaining = int(locked_until(vault["path"]) - time.time())
        raise LockedError(f"Trop de tentatives. Reessayez dans {remaining} secondes.")
    if not os.path.exists(vault["path"]):
        raise FileNotFoundError("Vault non trouve.")
```

**La fonction la plus complexe** : Ouvre un vault existant

**Partie 1 : Vérifications préliminaires**
1. **`if vault["loaded"]:`** : Déjà chargé → retourne immédiatement (idempotent)
2. **`if is_locked(vault["path"]):`** : Vérifie anti brute-force
3. **`if not os.path.exists(...):`** : Vérifie fichier existe

---

**Lecture header (Lignes 85-99) :**
```python
# On lit l'en-tete du vault pour obtenir le sel et la taille de l'index chiffré.
try:
    with open(vault["path"], "rb") as file:
        # On lit le magic, la version, le sel et la taille de l'index.
        magic = file.read(4)
        version = file.read(1)
        salt = file.read(SALT_SIZE)
        index_length_bytes = file.read(4)
        
        if magic != MAGIC:
            raise IntegrityError("Format de vault invalide.")
        if version != VERSION:
            raise IntegrityError("Version de vault non supportee.")
            
        index_length = struct.unpack("<I", index_length_bytes)[0]
```

**Processus :**
1. **`magic = file.read(4)`** : Lit "LBOX" (vérification format)
2. **`version = file.read(1)`** : Lit version (extensibilité)
3. **`salt = file.read(16)`** : Lit sel (pour `derive_key()`)
4. **`index_length_bytes = file.read(4)`** : Lit taille index
5. **`struct.unpack("<I", ...)`** : Décode little-endian → entier

**Vérifications :**
- Magic ≠ "LBOX" → vault corrompu ou mauvais format
- Version ≠ 0x01 → version incompatible

---

**Lecture et déchiffrement index (Lignes 100-117) :**
```python
# On dérive la clé à partir du mot de passe et du sel.
password_key = _password_key(vault, salt)

# On lit l'index chiffré.
encrypted_index = file.read(index_length)
if len(encrypted_index) != index_length:
    raise IntegrityError("Taille de l'index invalide.")

# On déchiffre l'index.
try:
    index_bytes = decrypt_data(password_key, encrypted_index)
except ValueError as exc:
    register_failed_attempt(vault["path"])
    raise IntegrityError("Mot de passe incorrect ou vault corrompu.") from exc

# On extrait la clé de données depuis l'index.
index = json.loads(index_bytes.decode("utf-8"))
wrapped_key_hex = index.pop("wrapped_key")
vault["key"] = decrypt_data(password_key, bytes.fromhex(wrapped_key_hex))
vault["index"] = index
vault["salt"] = salt
vault["loaded"] = True
reset_bruteforce(vault["path"])
```

**Séquence critique :**
1. **`password_key = _password_key(vault, salt)`** : Dérive clé mot de passe
2. **`encrypted_index = file.read(index_length)`** : Lit index chiffré
3. **`decrypt_data(password_key, encrypted_index)`** : **Point de vérification!**
   - Si tag invalide → `ValueError` → mauvais mot de passe ou altération
   - → `register_failed_attempt()` → compte échec
   - → `IntegrityError` avec message clair
4. **`json.loads(...)`** : Parse JSON déchiffré
5. **`index.pop("wrapped_key")`** : Extrait et retire wrapped_key de l'index
6. **`decrypt_data(...)`** : Déchiffre wrapped_key → obtient `data_key`
7. **Mise à jour vault dict** : Stocke toutes infos
8. **`reset_bruteforce(...)`** : Réinitialise compteur échecs (succès!)

---

### **`add_file(vault, file_path, name_in_vault)` (Lignes 136-160)**
```python
def add_file(vault: dict, file_path: str, name_in_vault: str | None = None) -> None:
    # Ajoute un fichier au vault en le chiffrant avec la clé de données.
    if not os.path.exists(vault["path"]):
        create_vault(vault)
        blobs = b""
    else:
        load_vault(vault)
        blobs = _read_blobs(vault)
    
    # rb/wb permettent de conserver exactement tous les octets du fichier.
    with open(file_path, "rb") as file:
        encrypted = encrypt_data(vault["key"], file.read())
    
    name = os.path.basename(file_path) if name_in_vault is None else name_in_vault
    vault["index"]["files"][name] = {"size": len(encrypted), "offset": 0}
    
    # On écrit le vault avec les blobs existants plus le nouveau fichier chiffré.
    _write_vault(vault, blobs + encrypted)
```

**Processus :**
1. **Vérifie existence vault** :
   - Si non existant → `create_vault()` (nouveau)
   - Si existant → `load_vault()` + `_read_blobs()` (lit tout)
2. **Lit fichier source** : `file.read()` (tout en mémoire)
3. **Chiffre** : `encrypt_data(vault["key"], ...)` avec `data_key`
4. **Prépare metadata** : Nom + taille chiffrée + offset temporaire 0
5. **Écrit** : `_write_vault(vault, blobs + encrypted)` ← Concaténation

**Important :** `blobs + encrypted` ajoute nouveau fichier à la fin

---

### **`extract_file(vault, filename, output_path)` (Lignes —)**
```python
def extract_file(vault: dict, filename: str, output_path: str | None = None) -> None:
    # Extrait un fichier du vault en le déchiffrant.
    load_vault(vault)
    
    if filename not in vault["index"]["files"]:
        raise FileNotFoundError(f"Fichier '{filename}' non trouve.")
    
    info = vault["index"]["files"][filename]
    with open(vault["path"], "rb") as file:
        file.seek(info["offset"])
        encrypted = file.read(info["size"])
    
    decrypted = decrypt_data(vault["key"], encrypted)
    
    output = output_path or filename
    with open(output, "wb") as file:
        file.write(decrypted)
```

**Logique :**
1. **`load_vault(vault)`** : Charge index (vérifie mot de passe)
2. **Vérifie existence** dans index
3. **`file.seek(info["offset"])`** : Saute directement à position fichier
4. **`file.read(info["size"])`** : Lit exactement taille connue
5. **`decrypt_data(vault["key"], encrypted)`** : Déchiffre avec `data_key`
6. **Écrit fichier déchiffré**

**Avantage offsets** : Accès direct O(1) sans parsing fichier complet

---

### **`delete_file(vault, filename)` (Lignes 185-199)**
```python
def delete_file(vault: dict, filename: str) -> None:
    # Supprime un fichier du vault.
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
```

**Stratégie :** Reconstruction complète sans le fichier supprimé

**Processus :**
1. **Lit vault** → charge index
2. **Parcourt tous fichiers** SAUF celui à supprimer
3. **Accumule** leurs données dans `bytearray`
4. **Supprime** entrée index
5. **Réécrit** vault avec fichiers restants

**Coût** : O(n) où n = taille totale fichiers (tout relu/réécrit)

---

### **`change_password(vault, new_password)` (Lignes 202-214)**
```python
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
```

**Ingéniosité** : Changement mot de passe SANS rechiffrement fichiers

**Pourquoi ça marche :**
1. **`load_vault(vault)`** : Obtient `data_key` (déchiffre wrapped_key)
2. **`_read_blobs(vault)`** : Lit fichiers chiffrés (déjà chiffrés avec `data_key`)
3. **Change password/salt** : Nouveau sel aléatoire
4. **`_write_vault(...)`** : Recrée wrapped_key avec nouveau password_key
5. **Fichiers inchangés** : Restent chiffrés avec même `data_key`

**Avantage majeur** : Rapide même pour gros vaults

---

## **5. SYSTÈME ANTI BRUTE-FORCE**

### **`_lock_path(vault_path)` (Lignes 217-221)**
```python
def _lock_path(vault_path: str) -> str:
    # Retourne le chemin du fichier de verrouillage associé au vault.
    lock_root = os.getenv("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), ".lockerbox")
    vault_id = hashlib.sha256(os.path.abspath(vault_path).encode("utf-8")).hexdigest()
    return os.path.join(lock_root, "LockerBox", "locks", f"{vault_id}.lock")
```

**Génération chemin unique par vault :**
1. **`os.getenv("LOCALAPPDATA")`** : Standard Windows pour données utilisateur
2. **Fallback** : `~/.lockerbox` si pas Windows
3. **`hashlib.sha256(...)`** : Hash du chemin absolu → identifiant unique
4. **Structure** : `.../LockerBox/locks/{hash}.lock`

**Pourquoi hash ?** : Éviter noms de fichiers problématiques (espaces, etc.)

---

### **`_load_lock_state(vault_path)` (Lignes 224-234)**
```python
def _load_lock_state(vault_path: str) -> dict:
    # Lit l'etat du verrou ou retourne un etat initial si absent/invalide.
    try:
        with open(_lock_path(vault_path), "r") as file:
            attempts, locked_until_value = file.read().strip().split(",")
            
            # On convertit les valeurs en types appropriés...
            return {"failed_attempts": int(attempts),
                    "locked_until": float(locked_until_value)}
    except (FileNotFoundError, ValueError):
        return {"failed_attempts": 0, "locked_until": 0.0}
```

**Format fichier lock :** `"2,1623456789.123"` (tentatives,timestamp)

**Robustesse** : `try/except` gère fichier absent/corrompu → état initial

---

### **`register_failed_attempt(vault_path)` (Lignes 255-263)**
```python
def register_failed_attempt(vault_path: str) -> None:
    # Ajoute un echec et active le verrou apres le nombre maximal d'essais.
    state = _load_lock_state(vault_path)
    state["failed_attempts"] += 1
    
    # Si le nombre d'échecs atteint le maximum, on verrouille le vault pour une durée définie.
    if state["failed_attempts"] >= MAX_ATTEMPTS:
        state["locked_until"] = time.time() + LOCK_DURATION
    _save_lock_state(vault_path, state)
```

**Logique :** Appelé quand `decrypt_data()` échoue dans `load_vault()`

**Politique :**
- Tentatives 1-2 : Incrémente compteur
- Tentative 3 : Verrouille 60 secondes
- Tentatives suivantes : Reste verrouillé jusqu'à expiration

---

## **6. PATTERNS ET CHOIX D'IMPLÉMENTATION**

### **Gestion mémoire :**
- **`bytearray()`** : Buffer mutable efficace pour accumulation données
- **`bytes()`** : Conversion finale pour données immuables
- **Tout en RAM** : Limite taille vault par mémoire disponible

### **Gestion fichiers :**
- **`"rb"`/`"wb"`** : Mode binaire pour données brutes (fichiers binaires/textes)
- **`file.seek()`** : Accès aléatoire pour efficacité
- **Pas de buffering** : Lecture/écriture directe

### **Gestion erreurs :**
- **Exceptions spécifiques** : `IntegrityError`, `LockedError`
- **Messages utilisateur clairs** : "Mot de passe incorrect ou vault corrompu"
- **Propagation** : Laisser exceptions remonter à CLI

### **Immutabilité :**
- **`dict(vault["index"])`** : Copie pour éviter modifications accidentelles
- **`bytes(blobs)`** : Conversion pour données immuables
- **Nouveau sel** : Toujours nouveau à chaque `change_password()`

### **Sécurité :**
- **`os.urandom()`** : Aléatoire cryptographique
- **Reset après succès** : `reset_bruteforce()` après bonne authentification
- **Données sensibles** : Clés jamais stockées en clair

---

## **7. POINTS D'ATTENTION POUR VOTRE ORAL**

### **À souligner :**
1. **`_set_offsets()` avec 2 itérations** : Garantit calcul précis taille index
2. **`_read_blobs()` pour reconstruction** : Approche simple mais coûteuse
3. **Changement mot de passe** : Sans rechiffrement grâce à architecture deux clés
4. **Anti brute-force** : Stocké séparément du vault (éviter suppression)
5. **Accès aléatoire** : Offsets permettent `seek()` direct

### **Questions techniques potentielles :**
**Q : Pourquoi tout recharger/réécrire pour chaque modification ?**  
**R :** Simplicité > Performance pour ce scope. Alternative : index chiffré incrémental.

**Q : Que se passe-t-il si crash pendant `_write_vault()` ?**  
**R :** Vault potentiellement corrompu. Solution : écrire temporaire puis rename atomique.

**Q : Pourquoi pas utiliser SQLite pour l'index ?**  
**R :** JSON + chiffrement suffit, évite dépendance, plus simple à déboguer.

**Q : Comment optimiser pour nombreux petits fichiers ?**  
**R :** Regrouper en blocs, index paginé, mais hors scope MVP.

### **Démonstration intéressante :**
1. **Montrer `_set_offsets()`** : Calcul dynamique positions
2. **Montrer `change_password()`** : Rapidité même sur gros vault
3. **Montrer `delete_file()`** : Reconstruction sans "trous"
4. **Montrer anti brute-force** : 3 tentatives → verrouillage

Cette analyse vous donne maintenant une compréhension approfondie de chaque fonction. Vous pouvez expliquer non seulement ce qu'elles font, mais aussi **pourquoi** elles sont implémentées ainsi !