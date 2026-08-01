# LockerBox

LockerBox est une solution de coffre-fort de fichiers local sécurisée, développée dans le cadre d'un projet de Bachelor 3 en Cybersécurité.

## Fonctionnalités
- Chiffrement authentifié (AES-256-GCM) pour chaque fichier.
- Dérivation de clé robuste (Argon2id).
- Interface CLI intuitive pour la gestion des fichiers.

## Installation
1. Cloner le dépôt : `git clone https://github.com/ZProtectt/LockerBox`
2. Créer un environnement virtuel : `python -m venv venv`
3. Installer les dépendances : `pip install -r requirements.txt`

## Utilisation
Utiliser le script `locker.bat` fourni :
- Initialiser : `.\locker.bat init mon_vault.dat`
- Ajouter : `.\locker.bat add mon_vault.dat mon_fichier.txt`
- Lister : `.\locker.bat list mon_vault.dat`
