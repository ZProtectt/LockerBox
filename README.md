# LockerBox – Coffre‑fort chiffré

LockerBox est un logiciel de coffre‑fort numérique conçu pour protéger vos fichiers
sensibles avec des algorithmes cryptographiques modernes. Il offre une interface
commande‑ligne simple et des fonctionnalités avancées comme le changement de mot
de passe sans rechiffrement et une protection anti‑bruteforce persistante.

## Fonctionnalités principales
- **Chiffrement hybride** : Une clé de données aléatoire chiffre les fichiers,
  elle‑même chiffrée par une clé dérivée du mot de passe.
- **Algorithme de chiffrement** : AES‑256‑GCM (confidentialité + intégrité).
- **Dérivation de clé** : Argon2id avec paramètres réglés pour une résistance
  élevée aux attaques par force brute.
- **Protection anti‑bruteforce** : Verrouillage temporaire après 3 tentatives
  erronées, persistant via un fichier `.lock`.
- **Changement de mot de passe transparent** : Seule la clé d’enveloppe est
  rechiffrée, les fichiers restent inchangés.
- **Interface CLI** : Commandes simples pour créer, remplir et consulter le
  vault, avec aide intégrée.

## Installation
Assurez‑vous d'avoir **Python 3.9 ou supérieur**.
```powershell
# Création et activation d'un environnement virtuel
python -m venv venv
.\venv\Scripts\activate

# Installation des dépendances
pip install -r requirements.txt
```
Les dépendances sont listées dans `requirements.txt` :
- `argon2‑cffi` : Dérivation de clé via Argon2id.
- `cryptography` : Chiffrement AES‑GCM.
- `click` : Interface CLI moderne.
- `pyinstaller` : Création d'un exécutable à partir du programme Python.

Pour créer un exécutable Windows après l'installation :
```powershell
pyinstaller --onefile --name LockerBox main.py
```
Le fichier sera créé dans le dossier `dist/`.

## Utilisation rapide
```powershell
# Créer un coffre
python main.py --vault mes_secrets.vault create

# Ajouter un fichier
python main.py --vault mes_secrets.vault add C:\Users\David\secret.txt

# Lister les fichiers
python main.py --vault mes_secrets.vault list-files

# Extraire un fichier
python main.py --vault mes_secrets.vault extract secret.txt C:\sortie.txt

# Supprimer un fichier
python main.py --vault mes_secrets.vault delete vieux_secret.txt

# Changer le mot de passe
python main.py --vault mes_secrets.vault change-password
```

## Architecture de sécurité
### Structure en deux clés
LockerBox utilise une architecture à deux clés :
1. **Clé de données (`key`)** : Aléatoire, de 32 octets, chiffre les fichiers.
2. **Clé de mot de passe (`password_key`)** : Dérivée du mot de passe via Argon2id.

La clé de données est chiffrée avec la clé de mot de passe et stockée dans l'index
sous forme de *wrapped_key*. Cela permet de changer le mot de passe sans toucher
aux fichiers.

### Format du fichier `.vault`
```
[4 octets] Signature "LBOX"
[1 octet]  Version (0x01)
[16 octets] Sel Argon2
[4 octets]  Taille de l'index chiffré (little‑endian)
[N octets] Index chiffré (nonce + ciphertext + tag)
[…]         Blobs des fichiers (nonce + ciphertext + tag par fichier)
```

Chaque fichier est lu comme une suite d'octets, puis chiffre avec AES-GCM.
L'utilisation de `rb` et `wb` permet de conserver les fichiers binaires sans
les convertir en texte.

### Vérification d'intégrité
Lors de l'ouverture, le programme déchiffre l'index et la clé de données
enveloppée. Cette étape vérifie le mot de passe et détecte une modification de
l'index. Lors de l'extraction, le blob du fichier est également vérifié par
AES-GCM avant son écriture sur le disque.

Le header contient des informations nécessaires à la lecture, mais n'est pas
un bloc AES-GCM séparé. Une modification du header peut donc provoquer une
erreur de format ou d'authentification plutôt qu'un message spécifique de
tampering.

### Anti‑bruteforce persistant
Lorsqu'une tentative d'authentification échoue, un fichier `.lock` est mis à jour
avec un compteur et un délai de verrouillage. Le mécanisme survit aux redémarrages
du programme. Après trois échecs consécutifs, le coffre est bloqué pendant 60
secondes.

## Documentation technique
- [`docs/threat_model.md`](docs/threat_model.md) : Modèle de menace complet.
- [`docs/vault_format.md`](docs/vault_format.md) : Spécifications du format binaire.
- Code source commenté dans `source/` et `main.py`.

## Licence
Projet académique – librement réutilisable pour des fins éducatives.
