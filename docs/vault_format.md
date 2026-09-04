# Spécification du Format de Vault : LockerBox (v1)

Ce document définit la structure binaire d'un fichier `.vault`. Le vault est conçu pour être sécurisé, authentifié et protégé contre l'altération.

## 1. Structure globale du fichier

Un fichier `.vault` est composé de trois sections séquentielles :

| Section | Taille | Contenu |
| :--- | :--- | :--- |
| **Header** | 25 octets | Données non chiffrées (Magic, Version, Salt, longueur de l'index) |
| **Index** | Variable | JSON chiffré (Métadonnées des fichiers) |
| **Data Blobs** | Variable | Contenu chiffré des fichiers |

---

## 2. Détail des sections

### A. Le Header (16 octets + 4 + 1 + 4)
C'est la partie lisible qui permet au logiciel de reconnaître le fichier et de préparer la dérivation de clé.

*   **Magic Number (4 octets) :** `"LBOX"` (Identifie le type de fichier).
*   **Version (1 octet) :** `0x01` (Permet des évolutions futures du format).
*   **Argon2 Salt (16 octets) :** Sel aléatoire généré lors de la création du vault.
*   **Index length (4 octets) :** Entier little-endian indiquant la taille de l'index chiffré.

### B. L'Index (Chiffré)
L'index est un objet JSON qui liste les fichiers contenus dans le vault. Il est chiffré avec la clé dérivée du mot de passe (via AES-GCM).

**Structure JSON avant chiffrement :**
```json
{
  "files": {
    "document.pdf": { "offset": 1024, "size": 5000 },
    "image.png": { "offset": 6024, "size": 12000 }
  },
  "wrapped_key": "..."
}
```
`wrapped_key` contient la clé aléatoire des fichiers, chiffrée avec la clé dérivée du mot de passe.
*   `offset` : Position absolue (en octets) où commencent les données chiffrées du fichier dans le vault.
*   `size` : Taille du contenu chiffré.

**Stockage de l'Index dans le fichier :**
Comme l'index est chiffré avec AES-GCM, il est stocké sous la forme :
`Nonce (12) + Ciphertext + Tag (16)`

### C. Data Blobs (Chiffrés)
Chaque fichier est chiffré individuellement avec son propre `Nonce`.
Pour chaque fichier stocké :
`Nonce (12) + Ciphertext + Tag (16)`

---

## 3. Procédure de lecture (Workflow)

1.  **Lire le Header :** Vérifier `"LBOX"`. Extraire le `Salt` et `index length`.
2.  **Dériver la clé :** Utiliser `Argon2id(password, salt)` pour obtenir `PasswordKey`.
3.  **Déchiffrer l'Index :**
    *   Lire `Nonce`, `Tag` et `Ciphertext` de la section Index.
    *   `AESGCM(PasswordKey).decrypt(nonce, ciphertext, tag)`.
    *   Déchiffrer `wrapped_key` avec `PasswordKey` pour obtenir la clé de données.
    *   Si l'erreur `InvalidTag` survient : **Le mot de passe est faux ou le vault est corrompu.**
4.  **Accéder aux données :** Utiliser la clé de données et les informations de l'index pour lire `offset` et `size` octets.
5.  **Vérifier un fichier :** Lors de l'extraction, déchiffrer son blob avec
  AES-GCM. Le tag vérifie l'intégrité du fichier avant son écriture.

L'ouverture vérifie donc immédiatement l'index, mais les blobs des fichiers
sont vérifiés lorsqu'ils sont extraits. Le header est lu avant le déchiffrement
et n'est pas authentifié par un tag AES-GCM séparé.

---

## 4. Pourquoi ce design est sécurisé

1.  **Indépendance des fichiers :** Chaque fichier a son propre `Nonce`. Même si tu stockes deux fois le même fichier, leurs contenus chiffrés seront différents.
2.  **Protection contre l'altération (Tampering) :** Grâce à **AES-GCM**, si un attaquant modifie un seul octet de l'index ou d'un blob chiffré, le `Tag` ne correspondra plus. La bibliothèque de chiffrement lèvera une exception lors de l'ouverture pour l'index, ou lors de l'extraction pour le fichier concerné.
3.  **Confidentialité des métadonnées :** L'index est chiffré. Un attaquant ne peut pas savoir quels sont les noms des fichiers contenus dans le vault.
