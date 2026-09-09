Parfait ! Maintenant je vais analyser la structure et vous préparer un guide complet.

---

# **Guide Complet pour votre Soutenance - Cheatsheet des Fonctions**

## **1. STRUCTURE GLOBALE DU PROJET**

### **Architecture à 3 couches :**
```
┌─────────────────┐
│    MAIN (CLI)    │ ← Interface utilisateur (Click)
├─────────────────┤
│      VAULT       │ ← Gestion du vault (logique métier)
├─────────────────┤
│     CRYPTO       │ ← Opérations cryptographiques (bas niveau)
└─────────────────┘
```

### **Flux de données :**
```
Utilisateur → CLI → Vault → Crypto → Fichier .vault
```

---

## **2. MODULE CRYPTO (crypto.py) - LE COEUR CRYPTOGRAPHIQUE**

### **`derive_key(password, salt, key_length=32)`**
**Rôle** : Transforme un mot de passe faible en clé cryptographique forte  
**Fonction** : Dérivation de clé avec Argon2id  
**Entrée** : Mot de passe (str) + Sel (16 octets)  
**Sortie** : Clé de 32 octets (256 bits)  
**Pourquoi ?** : Protège contre les attaques brute-force  
**Paramètres sécurité** : 
- `time_cost=3` (lent)
- `memory_cost=65536` (64 Mo, coûteux)
- `parallelism=4` (optimisé CPU)

### **`encrypt_data(key, data)`**
**Rôle** : Chiffre des données avec authentification  
**Fonction** : Chiffrement AES-256-GCM  
**Entrée** : Clé (32 octets) + Données brutes  
**Sortie** : Nonce (12) + Données chiffrées + Tag (16)  
**Pourquoi GCM ?** : Chiffrement + Authentification en une opération  
**Garantie** : Si données modifiées → Tag invalide → Détection altération

### **`decrypt_data(key, payload)`**
**Rôle** : Déchiffre et vérifie l'intégrité  
**Fonction** : Déchiffrement AES-256-GCM avec vérification  
**Entrée** : Clé + (Nonce + Données chiffrées + Tag)  
**Sortie** : Données originales OU exception  
**Détection** : Lance `ValueError("Tampering détecté")` si tag invalide

---

## **3. MODULE VAULT (vault.py) - LA LOGIQUE MÉTIER**

### **Fonctions principales :**

### **`new_vault(vault_path, password)`**
**Rôle** : Crée un objet vault en mémoire  
**Sortie** : Dictionnaire avec état initial  
**Contenu** : Chemin, mot de passe, index vide, sel/clé à None

### **`create_vault(vault)`**
**Rôle** : Crée un nouveau vault **sur disque**  
**Actions** :
1. Génère sel aléatoire (16 octets)
2. Génère clé de données aléatoire (32 octets)
3. Initialise index vide
4. Écrit fichier .vault avec header

### **`load_vault(vault)`**
**Rôle** : **La fonction la plus importante** - Ouvre un vault existant  
**Processus** :
1. Vérifie verrouillage (trop de tentatives)
2. Lit header (magic "LBOX", version, sel, taille index)
3. Dérive clé avec Argon2id
4. Déchiffre index avec AES-GCM
5. Extrait clé de données
6. **Si échec** → Altération détectée ou mauvais mot de passe

### **`add_file(vault, file_path, name_in_vault)`**
**Rôle** : Ajoute un fichier au vault  
**Processus** :
1. Lit fichier source
2. Chiffre avec AES-GCM (nouveau nonce)
3. Met à jour index avec offset/taille
4. Réécrit vault complet

### **`extract_file(vault, filename, output_path)`**
**Rôle** : Extrait un fichier du vault  
**Processus** :
1. Vérifie fichier existe dans index
2. Lit données à offset spécifique
3. Déchiffre avec vérification tag
4. Écrit fichier déchiffré
5. **Garantie** : Si fichier modifié → échec déchiffrement

### **`delete_file(vault, filename)`**
**Rôle** : Supprime un fichier du vault  
**Astuce** : Réécrit vault sans le fichier (pas de "trous")

### **`change_password(vault, new_password)`**
**Rôle** : Change le mot de passe **sans rechiffrer les fichiers**  
**Smart design** : 
- Change seulement sel Argon2
- Rechiffre `wrapped_key` (clé de données)
- **Les fichiers restent chiffrés avec la même clé de données**

### **`list_files(vault)`**
**Rôle** : Liste fichiers dans le vault  
**Info** : Index est chiffré → seulement accessible après `load_vault()`

---

## **4. SYSTÈME ANTI BRUTE-FORCE**

### **`register_failed_attempt(vault_path)`**
**Rôle** : Compte les échecs de connexion  
**Seuil** : 3 tentatives → verrouillage 60 secondes

### **`is_locked(vault_path)`** 
**Rôle** : Vérifie si vault est temporairement verrouillé

### **`reset_bruteforce(vault_path)`**
**Rôle** : Réinitialise compteur après succès

### **Stockage** : Fichier dans `%LOCALAPPDATA%\LockerBox\locks\`

---

## **5. FONCTIONS INTERNES (à connaître mais pas détailler)**

### **`_password_key(vault, salt)`**
**Rôle** : Appelle `derive_key()` - couche d'abstraction

### **`_index_bytes(vault, password_key)`**
**Rôle** : Prépare index JSON pour chiffrement  
**Ajoute** : `wrapped_key` (clé de données chiffrée)

### **`_set_offsets(vault, password_key)`**
**Rôle** : Calcule positions fichiers dans vault  
**Pourquoi ?** : Chaque fichier a offset unique pour accès direct

### **`_write_vault(vault, blobs)`**
**Rôle** : Écrit structure complète sur disque  
**Structure** : Header + Index chiffré + Blobs fichiers

### **`_read_blobs(vault)`**
**Rôle** : Lit tous blobs fichier pour opérations globales

---

## **6. ARCHITECTURE À DEUX CLÉS (LE CONCEPT CLÉ)**

### **Clé de mot de passe (`password_key`)**
- **Source** : Dérivée du mot de passe via Argon2id
- **Usage** : Chiffre/déchiffre `wrapped_key`
- **Stockage** : Jamais stockée, régénérée à l'ouverture

### **Clé de données (`key`)**
- **Source** : 32 octets aléatoires
- **Usage** : Chiffre/déchiffre **les fichiers**
- **Stockage** : Chiffrée dans `wrapped_key` (dans index)

### **Avantages :**
1. **Changement mot de passe rapide** : Seule `wrapped_key` mise à jour
2. **Performance** : Clé de données réutilisée pour tous fichiers
3. **Sécurité** : Deux couches indépendantes

---

## **7. STRUCTURE DU FICHIER .VAULT**

```
[HEADER - 25 octets]
├── "LBOX" (4) - Signature
├── Version (1) - 0x01
├── Sel Argon2 (16) - Pour derive_key()
└── Taille Index (4) - Little-endian

[INDEX - Variable]
├── Nonce (12) - Pour AES-GCM
├── Données chiffrées
└── Tag (16) - Vérification intégrité
    Contenu : {"files": {...}, "wrapped_key": "..."}

[DATA BLOBS - Variable]
├── Fichier 1 : Nonce + Chiffré + Tag
├── Fichier 2 : Nonce + Chiffré + Tag
└── ...
```

---

## **8. FLUX COMPLET D'UNE OPÉRATION**

### **Ajout fichier :**
```
1. load_vault() → déchiffre index
2. read_file() → lit fichier source  
3. encrypt_data(data_key, file_data) → chiffre
4. update_index() → ajoute offset/taille
5. _write_vault() → réécrit tout
```

### **Ouverture vault :**
```
1. check_lock() → anti brute-force
2. read_header() → extrait sel
3. derive_key() → crée password_key
4. decrypt_data() → déchiffre index
5. extract wrapped_key → obtient data_key
6. SI tag invalide → "Tampering détecté"
```

---

## **9. POINTS FORTS À SOULIGNER**

### **Sécurité :**
1. **Argon2id** : Protection contre attaques brute-force
2. **AES256-GCM** : Chiffrement authentifié (détection altération)
3. **Deux clés** : Séparation des préoccupations
4. **Anti brute-force** : Verrouillage après 3 échecs

### **Design intelligent :**
1. **Changement mot de passe** : Sans rechiffrement fichiers
2. **Nonce unique** : Par fichier, garantit unicité
3. **Offset calculés** : Accès direct sans parsing
4. **Intégrité vérifiée** : À l'ouverture ET à l'extraction

### **Robustesse :**
1. **Exception handling** : Détection corruption
2. **Type checking** : Validation entrées
3. **Atomic writes** : Pas d'état corrompu
4. **Lock files** : Protection concurrente

---

## **10. POUR VOTRE ORAL - SYNTHÈSE**

### **En 3 phrases :**
"Lockerbox utilise **Argon2id** pour transformer votre mot de passe en une clé forte, et **AES256-GCM** pour protéger chaque fichier avec un sceau cryptographique. L'**architecture à deux clés** permet de changer de mot de passe sans tout rechiffrer, et le **système anti brute-force** bloque les attaques après 3 tentatives."

### **Le message clé :**
"**Même si quelqu'un vole votre disque dur, il ne peut ni deviner votre mot de passe (Argon2id), ni modifier vos fichiers sans être détecté (AES-GCM), ni forcer l'accès par essais répétés (anti brute-force).**"

### **La démo convaincante :**
1. Montrez création vault (génération sel/clé)
2. Ajoutez fichier (chiffrement avec nonce unique)
3. Modifiez octet dans hex editor
4. Montrez "Tampering détecté" à l'ouverture
5. Changez mot de passe (rapide, pas de rechiffrement)

---

## **11. CHEATSHE FINALE POUR VOTRE PRÉPARATION**

### **À savoir expliquer :**
- [ ] `derive_key()` : Mot de passe → Clé forte (Argon2id)
- [ ] `encrypt_data()`/`decrypt_data()` : Chiffrement avec tag (AES-GCM)
- [ ] `load_vault()` : Processus complet d'ouverture
- [ ] Architecture deux clés : `password_key` vs `data_key`
- [ ] Structure fichier .vault : Header + Index + Blobs
- [ ] Anti brute-force : Verrouillage 60s après 3 échecs

### **Questions potentielles & réponses :**
**Q : "Pourquoi deux clés ?"**  
**R :** Performance (changement mot de passe rapide) + Séparation sécurité

**Q : "Que se passe-til si le nonce est réutilisé ?"**  
**R :** Catastrophe sécurité ! Heureusement, `os.urandom()` garantit unicité.

**Q : "Pourquoi JSON pour l'index ?"**  
**R :** Lisibilité + Extensibilité + Facile à parser

**Q : "Pourquoi réécrire tout le vault pour une modification ?"**  
**R :** Garantie cohérence + Pas de fragmentation + Simple

### **Le pitch final :**
"**J'ai construit Lockerbox autour de trois principes : rendre les attaques coûteuses (Argon2id), détecter toute modification (AES-GCM), et offrir une expérience utilisateur sécurisée mais pratique.**"

---

**Prochain prompt** : Je pourrai vous aider avec les détails d'implémentation spécifiques, les tests à montrer, ou la préparation des réponses aux questions techniques !