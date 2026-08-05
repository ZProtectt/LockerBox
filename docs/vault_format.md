# Spécification du Format de Vault : LockerBox (v1)

Ce document définit la structure binaire d'un fichier `.vault`. Le vault est conçu pour être sécurisé, authentifié et protégé contre l'altération.

## 1. Structure globale du fichier

Un fichier `.vault` est composé de trois sections séquentielles :

| Section | Taille | Contenu |
| :--- | :--- | :--- |
| **Header** | 21 octets | Données non chiffrées (Magic, Version, Salt) |
| **Index** | Variable | JSON chiffré (Métadonnées des fichiers) |
| **Data Blobs** | Variable | Contenu chiffré des fichiers |

---

## 2. Détail des sections

### A. Le Header (16 octets + 4 + 1)
C'est la partie lisible qui permet au logiciel de reconnaître le fichier et de préparer la dérivation de clé.

*   **Magic Number (4 octets) :** `"LBOX"` (Identifie le type de fichier).
*   **Version (1 octet) :** `0x01` (Permet des évolutions futures du format).
*   **Argon2 Salt (16 octets) :** Sel aléatoire généré lors de la création du vault.

### B. L'Index (Chiffré)
L'index est un objet JSON qui liste les fichiers contenus dans le vault. Il est chiffré avec la clé dérivée du mot de passe (via AES-GCM).

**Structure JSON :**
```json
{
  "files": {
    "document.pdf": { "offset": 1024, "size": 5000 },
    "image.png": { "offset": 6024, "size": 12000 }
  }
}
```
*   `offset` : Position absolue (en octets) où commencent les données chiffrées du fichier dans le vault.
*   `size` : Taille du contenu chiffré.

**Stockage de l'Index dans le fichier :**
Comme l'index est chiffré avec AES-GCM, il est stocké sous la forme :
`Nonce (12) + Tag (16) + Ciphertext`

### C. Data Blobs (Chiffrés)
Chaque fichier est chiffré individuellement avec son propre `Nonce`.
Pour chaque fichier stocké :
`Nonce (12) + Tag (16) + Ciphertext`

---

## 3. Procédure de lecture (Workflow)

1.  **Lire le Header :** Vérifier `"LBOX"`. Extraire le `Salt`.
2.  **Dériver la clé :** Utiliser `Argon2id(password, salt)` pour obtenir `MasterKey`.
3.  **Déchiffrer l'Index :**
    *   Lire `Nonce`, `Tag` et `Ciphertext` de la section Index.
    *   `AESGCM(MasterKey).decrypt(nonce, ciphertext, tag)`.
    *   Si l'erreur `InvalidTag` survient : **Le mot de passe est faux ou le vault est corrompu.**
4.  **Accéder aux données :** Utiliser les informations de l'index pour sauter (`seek`) à la position `offset` et lire `size` octets.

---

## 4. Pourquoi ce design est sécurisé

1.  **Indépendance des fichiers :** Chaque fichier a son propre `Nonce`. Même si tu stockes deux fois le même fichier, leurs contenus chiffrés seront différents.
2.  **Protection contre l'altération (Tampering) :** Grâce à **AES-GCM**, si un attaquant modifie un seul octet du fichier chiffré (dans l'index ou dans les données), le `Tag` ne correspondra plus. La bibliothèque de chiffrement lèvera une exception automatiquement lors du déchiffrement.
3.  **Confidentialité des métadonnées :** L'index est chiffré. Un attaquant ne peut pas savoir quels sont les noms des fichiers contenus dans le vault.
