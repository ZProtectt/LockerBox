# Modèle de menace - LockerBox

## 1. Objectifs de sécurité
Le projet LockerBox vise à protéger des fichiers sensibles stockés sur un système potentiellement compromis ou volé.
Les propriétés de sécurité recherchées sont :
- **Confidentialité :** Seul l'utilisateur connaissant le mot de passe maître peut accéder au contenu des fichiers.
- **Intégrité :** Toute modification non autorisée du fichier `.vault` (volontaire ou due à une corruption) est détectée.
- **Authentification :** Protection contre les attaques par force brute sur le mot de passe maître.

## 2. Acteurs et vecteurs d'attaque
- **Attaquant local/physique :** A accès au fichier `.vault` et veut lire son contenu sans le mot de passe.
- **Malware :** Tente de modifier le fichier `.vault` pour corrompre les données ou injecter du code.
- **Attaquant distant :** Tente de récupérer des fichiers via une intrusion système.

## 3. Atténuations
- **Argon2id :** Utilisation pour la dérivation de clé afin de rendre les attaques par force brute (sur le mot de passe) extrêmement coûteuses en temps et en mémoire.
- **AES-256-GCM :** Chiffrement authentifié garantissant que si le fichier `.vault` est modifié, le déchiffrement échouera (détection d'intégrité).
- **Index chiffré :** Empêche de connaître la structure ou les noms des fichiers présents dans le vault sans la clé.
- **Clé de données intermédiaire :** La clé des fichiers est aléatoire et seule son enveloppe est modifiée lors d'un changement de mot de passe.
- **Verrouillage temporaire :** L'interface bloque les nouvelles tentatives après trois échecs pendant 60 secondes.

## 4. Limites
- **Sécurité du mot de passe :** Si le mot de passe maître est faible, la sécurité globale est compromise.
- **Protection contre les attaques de type "Cold Boot" ou "Memory dumping" :** La clé maître est présente en mémoire pendant l'exécution du programme.
- **Suppression non sécurisée :** Actuellement, le vault ne réécrit pas le fichier en effaçant les anciennes données après suppression (nécessiterait un overwrite sécurisé).
