# LockerBox

LockerBox est un coffre-fort numérique sécurisé pour protéger vos fichiers sensibles.

## Fonctionnalités
- **Chiffrement Authentifié :** Utilise AES-256-GCM pour garantir confidentialité et intégrité.
- **Dérivation de clé sécurisée :** Utilise Argon2id pour protéger le mot de passe maître.
- **Interface CLI :** Gestion simple des fichiers (création, ajout, listing, extraction).

## Installation
Assurez-vous d'avoir Python 3 installé.
```powershell
# Création et activation de l'environnement virtuel
python -m venv venv
.\venv\Scripts\activate

# Installation des dépendances
pip install -r requirements.txt
```

## Utilisation
```powershell
# Initialiser un vault
python main.py --vault mon_coffre.vault create

# Ajouter un fichier
python main.py --vault mon_coffre.vault add secret.txt

# Lister les fichiers
python main.py --vault mon_coffre.vault list

# Extraire un fichier
python main.py --vault mon_coffre.vault extract secret.txt restauration.txt
```

## Sécurité
Voir [docs/threat_model.md](docs/threat_model.md) pour le modèle de menace détaillé.
