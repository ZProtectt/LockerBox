# Modèle de Menace : LockerBox - Vault de Fichiers Sécurisé

**Version :** 1.0
**Auteur :** [Ton Nom]
**Date :** 2026-08-01
**Projet :** Projet Annuel - Bachelor 3 Cybersécurité

---

## 1. Introduction
Ce document présente le modèle de menace pour **LockerBox**, une solution de coffre-fort numérique local. L'objectif est d'identifier les vecteurs d'attaque potentiels et de documenter les mesures cryptographiques mises en place pour assurer la confidentialité, l'intégrité et l'authenticité des données stockées.

## 2. Périmètre (Scope)
LockerBox est une application locale. Le périmètre inclut :
*   Le processus de dérivation de clé (KDF).
*   Le chiffrement des fichiers.
*   La structure du fichier de stockage (Vault).
*   L'interface utilisateur (CLI/GUI).

**Hors périmètre :** La sécurité au niveau du système d'exploitation hôte (si la machine est compromise par un rootkit ou un keylogger, la sécurité de l'application est nulle).

## 3. Actifs (Assets)
| Actif | Description | Objectif de sécurité |
| :--- | :--- | :--- |
| **Fichiers utilisateurs** | Données confidentielles stockées dans le vault | Confidentialité, Intégrité |
| **Mot de passe maître** | Clé secrète de déverrouillage | Confidentialité (Doit être non réversible) |
| **Métadonnées** | Noms de fichiers, tailles | Confidentialité |

## 4. Analyse des menaces (Méthodologie STRIDE)

| Catégorie | Menace | Impact | Atténuation (Mitigation) |
| :--- | :--- | :--- | :--- |
| **S**poofing | Usurpation d'identité | Peu applicable (Local) | N/A |
| **T**ampering | Modification illicite des données du vault | Corruption ou modification de données | Utilisation d'AES-GCM (Chiffrement Authentifié). Tout bit modifié entraîne un échec de déchiffrement. |
| **R**epudiation | Répudiation | Peu applicable (Local) | N/A |
| **I**nformation Disclosure | Divulgation d'informations (Brute-force) | Accès aux fichiers confidentiels | Utilisation de **Argon2id** (KDF) avec salt unique pour ralentir massivement le brute-force. |
| **D**enial of Service | Déni de service | Perte d'accès aux données | Gestion des backups utilisateur (Rappel : Pas de cloud). |
| **E**levation of Privilege | Élévation de privilèges | Accès aux fichiers via un autre compte OS | Respect des permissions fichiers du système d'exploitation hôte. |

## 5. Mesures Cryptographiques et Justifications

### 5.1. Dérivation de clé (KDF) : Argon2id
*   **Pourquoi :** C'est le vainqueur de la Password Hashing Competition. Il est conçu pour résister aux attaques GPU/ASIC en utilisant une consommation mémoire configurable.
*   **Implémentation :** Salt généré aléatoirement (`os.urandom(16)`), stockage du salt en clair dans le header du vault pour permettre la re-dérivation.

### 5.2. Chiffrement : AES-256-GCM
*   **Pourquoi :** AES est le standard industriel. Le mode GCM (Galois/Counter Mode) offre un chiffrement **authentifié**. Contrairement au mode CBC, il garantit que si une seule donnée chiffrée est modifiée, le tag d'intégrité ne correspondra plus, et le déchiffrement échouera.
*   **Implémentation :** Chaque fichier est chiffré individuellement avec un **Nonce unique** de 12 octets.

## 6. Limites connues (Assumptions & Limitations)

1.  **Sécurité au repos (OS) :** Si l'attaquant possède des accès administrateur sur la machine hôte et installe un keylogger, le mot de passe maître sera capturé avant même d'atteindre l'application.
2.  **Perte du mot de passe :** Aucun mécanisme de "récupération de mot de passe" n'est implémenté par conception. La perte du mot de passe maître entraîne la perte définitive des données.
3.  **Analyse de trafic (Métadonnées) :** Le nom des fichiers et leur taille ne sont pas chiffrés dans l'index. Un attaquant peut donc déduire des informations sur le contenu du vault par l'analyse des tailles et noms de fichiers (ex: `rapport_licenciements.pdf`).
    *   *Note pour le jury :* Une évolution future consisterait à chiffrer l'index du vault.

## 7. Conclusion
L'architecture de LockerBox repose sur des standards cryptographiques robustes (AES-GCM, Argon2id). Bien que l'application ne protège pas contre une compromission totale du système d'exploitation, elle remplit son objectif de protection des données contre une analyse statique du fichier vault ou une tentative de force brute.
