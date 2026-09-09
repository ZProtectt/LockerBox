Parfait ! Voici une liste complète de 40 questions couvrant tous les aspects de votre projet, du plus basique au plus technique.

---

# **40 QUESTIONS POUR VOTRE PRÉPARATION À LA SOUTENANCE**

## **CATÉGORIE 1 : QUESTIONS GÉNÉRALES (Basique)**

**1. Qu'est-ce que Lockerbox en une phrase ?**
*(Réponse attendue : Un coffre-fort chiffré pour fichiers avec interface CLI)*

**2. Pourquoi avoir choisi Python pour ce projet ?**
*(Avantages : Rapidité développement, bibliothèques crypto solides, portabilité)*

**3. Quelle est la différence fondamentale entre chiffrement symétrique et asymétrique ?**
*(Symétrique : Même clé pour chiffrer/déchiffre, plus rapide)*

**4. Pourquoi utiliser Click pour l'interface CLI ?**
*(Modernité, auto-génération help, gestion arguments, meilleur que argparse)*

**5. Quel est le public cible de Lockerbox ?**
*(Utilisateurs techniques voulant sécuriser fichiers localement)*

**6. Quelle est la taille minimale d'un vault vide ?**
*(25 octets header + overhead index chiffré)*

**7. Pourquoi le format .vault et pas .zip ou autre ?**
*(Format propriétaire optimisé sécurité, pas compression)*

---

## **CATÉGORIE 2 : ARCHITECTURE & DESIGN**

**8. Pourquoi une architecture à deux clés ?**
*(Performance : changement mot de passe rapide + Séparation sécurité)*

**9. Quelle est la différence entre password_key et data_key ?**
*(password_key : dérivée du mot de passe, data_key : aléatoire, chiffre fichiers)*

**10. Pourquoi chiffrer l'index JSON ?**
*(Confidentialité métadonnées : cacher noms fichiers)*

**11. Pourquoi réécrire tout le vault pour ajouter/supprimer un fichier ?**
*(Simplicité, cohérence, pas de fragmentation)*

**12. Pourquoi stocker le salt dans le header en clair ?**
*(Nécessaire pour recalculer la clé, pas secret)*

**13. Pourquoi utiliser JSON pour l'index plutôt qu'un format binaire ?**
*(Lisibilité debug, extensibilité, facile parser)*

**14. Comment gérez-vous les accès concurrents au même vault ?**
*(Pas besoin : usage mono-utilisateur, mais lock files anti-brute)*

---

## **CATÉGORIE 3 : CRYPTOGRAPHIE BASIQUE**

**15. Pourquoi Argon2id et pas SHA256 ou MD5 ?**
*(Argon2id : conçu pour hachage mots de passe, résistant GPU/ASIC)*

**16. Qu'est-ce qu'un "salt" et pourquoi est-il nécessaire ?**
*(Valeur aléatoire empêchant rainbow tables, différente par vault)*

**17. Pourquoi AES-256 et pas AES-128 ou AES-192 ?**
*(256 bits = sécurité future-proof, standard industriel)*

**18. Quelle est la différence entre AES et AES-GCM ?**
*(GCM ajoute authentification = chiffrement + vérification intégrité)*

**19. Qu'est-ce qu'un "nonce" et pourquoi doit-il être unique ?**
*(Nombre à usage unique, garantit unicité sortie chiffrée)*

**20. Que se passe-t-il si on réutilise un nonce avec la même clé ?**
*(Catastrophe sécurité : peut révéler informations)*

**21. Quelle est la taille de la clé dans votre projet ?**
*(32 octets = 256 bits pour AES-256)*

---

## **CATÉGORIE 4 : IMPLÉMENTATION TECHNIQUE**

**22. Comment générez-vous les valeurs aléatoires (salt, nonce, clé) ?**
*(os.urandom() : cryptographiquement sécurisé)*

**23. Pourquoi utiliser des exceptions pour gérer les erreurs ?**
*(Clarté, propagation automatique, meilleur contrôle flux)*

**24. Comment détectez-vous une altération (tampering) ?**
*(Tag AES-GCM invalide → exception InvalidTag)*

**25. Pourquoi utilisez-vous try/except dans decrypt_data ?**
*(Capturer InvalidTag spécifiquement pour message clair)*

**26. Comment calculez-vous les offsets des fichiers dans le vault ?**
*(HEADER_SIZE + taille_index + accumulation tailles précédentes)*

**27. Pourquoi hex() pour wrapped_key dans l'index ?**
*(Représentation texte JSON-compatible)*

**28. Comment gérez-vous les fichiers binaires vs texte ?**
*(Traitement octets bruts, pas de conversion texte)*

---

## **CATÉGORIE 5 : SÉCURITÉ AVANCÉE**

**29. Comment protégez-vous contre les attaques brute-force ?**
*(Verrouillage 60s après 3 échecs, compteur dans %LOCALAPPDATA%)*

**30. Pourquoi 3 tentatives et pas 5 ou 10 ?**
*(Équilibre sécurité/commodité, standard industriel)*

**31. Pourquoi le verrouillage dure 60 secondes et pas plus/moins ?**
*(Suffisant décourager automatisation, pas trop gênant utilisateur)*

**32. Où stockez-vous le compteur d'échecs et pourquoi là ?**
*(%LOCALAPPDATA% : séparé du vault, persistant, utilisateur)*

**33. Comment prévenez-vous les attaques par canaux auxiliaires ?**
*(Argon2id résistant, timing constant pour comparaison)*

**34. Pourquoi paramétrer Argon2id avec memory_cost=65536 ?**
*(64 Mo = coûteux pour GPU, difficile attaque matérielle)*

**35. Que se passe-t-il si un attaquant clone le vault et essaie plusieurs mots de passe ?**
*(Verrouillage lié au chemin, clones indépendants)*

---

## **CATÉGORIE 6 : QUESTIONS TECHNIQUES AVANCÉES**

**36. Comment fonctionne exactement le XOR dans AES-GCM ?**
*(Flux pseudo-aléatoire ⊕ données = chiffré, même processus déchiffrement)*

**37. Pourquoi GCM génère-t-il un tag de 16 octets ?**
*(Taille standard AES-GCM, équilibre sécurité/overhead)*

**38. Que contient exactement le tag d'authentification ?**
*(Empreinte cryptographique des données + clé + nonce)*

**39. Pourquoi utiliser le mode compteur (CTR) dans GCM ?**
*(Parallélisation, pas propagation erreurs, efficace gros fichiers)*

**40. Comment Argon2id rend-il les attaques GPU coûteuses ?**
*(Besoin mémoire importante = GPU inefficaces)*

**41. Quelle serait l'impact d'augmenter time_cost de 3 à 10 ?**
*(Sécurité ↑ mais expérience utilisateur ↓, compromis)*

**42. Comment testeriez-vous la robustesse cryptographique ?**
*(Tests unitaires, fuzzing, vérification bibliothèques)*

**43. Que se passe-t-il si le header est corrompu ?**
*(Lecture échoue (magic "LBOX" invalide) ou valeurs incohérentes)*

**44. Pourquoi le header n'est-il pas authentifié par un tag ?**
*(Nécessaire lecture avant déchiffrement, vérifié par logique)*

---

## **CATÉGORIE 7 : SCÉNARIOS & CAS LIMITES**

**45. Que fait Lockerbox si le disque est plein pendant écriture ?**
*(Exception IOError, vault potentiellement corrompu)*

**46. Comment gérez-vous les noms de fichiers identiques ?**
*(Écrasement (overwrite) ou erreur selon implémentation)*

**47. Que se passe-t-il si on essaie d'extraire un fichier inexistant ?**
*(FileNotFoundError avec message clair)*

**48. Comment récupérer un vault si on oublie le mot de passe ?**
*(Impossible par design - c'est une feature, pas un bug)*

**49. Que faire si le fichier .lock est supprimé manuellement ?**
*(Compteur reset, attaquant peut réessayer)*

**50. Supportez-vous les fichiers de très grande taille (>4GB) ?**
*(Théoriquement oui (Python bytes), limité par RAM)*

**51. Comment le vault évolue avec plusieurs ajouts/suppressions ?**
*(Fragmentation virtuelle mais stocké contigu en réalité)*

---

## **CATÉGORIE 8 : QUESTIONS PIÈGES / CRITIQUES**

**52. Pourquoi ne pas utiliser de compression avant chiffrement ?**
*(Compression peut révéler informations, KISS principle)*

**53. Pourquoi ne pas utiliser de chiffrement asymétrique pour partage ?**
*(Scope projet : coffre-fort personnel, pas partage)*

**54. Pourquoi ne pas chiffrer les noms de fichiers individuellement ?**
*(Index entier chiffré = même protection)*

**55. Pourquoi Python et pas C++ pour meilleures performances ?**
*(Trade-off : développement rapide vs optimisation extrême)*

**56. Pourquoi pas de GUI (interface graphique) ?**
*(Scope projet CLI, utilisateurs techniques)*

**57. Comment compareriez-vous Lockerbox à VeraCrypt ?**
*(VeraCrypt : volumes, plus complexe. Lockerbox : fichiers simples)*

**58. Pourquoi réinventer la roue vs utiliser GPG ou autre ?**
*(Apprentissage, contrôle total, solution intégrée)*

---

## **CATÉGORIE 9 : ÉVOLUTION & AMÉLIORATIONS**

**59. Quelles améliorations prévoiriez-vous pour V2 ?**
*(Compression, déduplication, index chiffré incrémental)*

**60. Comment ajouteriez-vous le support multi-utilisateurs ?**
*(Chiffrement asymétrique pour partage clés)*

**61. Comment implémenteriez-vous la récupération mot de passe ?**
*(Question secrète → sel, mais mauvaise pratique)*

**62. Comment ajouter du chiffrement hybride (symétrique + asymétrique) ?**
*(Clé session symétrique chiffrée avec clé publique)*

**63. Comment optimiseriez-vous pour très nombreux petits fichiers ?**
*(Regroupement blocs, index paginé)*

**64. Comment ajouteriez-vous l'intégration cloud ?**
*(Vault synchronisé, clés locales)*

---

## **CATÉGORIE 10 : CONNAISSANCE CODE (Important!)**

**65. Quelle ligne de code montre la détection d'altération ?**
*(Ligne 62 : `raise ValueError("Tampering détecté.")`)*

**66. Où sont définis les paramètres Argon2id dans le code ?**
*(Lignes 25-29 : time_cost=3, memory_cost=65536, etc.)*

**67. Comment est structuré le dictionnaire vault en mémoire ?**
*(path, password, index, salt, key, loaded)*

**68. Quelle fonction appelle derive_key() indirectement ?**
*(_password_key() qui est appelée par load_vault())*

**69. Où se trouve la logique de calcul des offsets ?**
*(_set_offsets() appelée par _write_vault())*

**70. Comment le nonce est-il extrait lors du déchiffrement ?**
*(payload[:NONCE_SIZE] ligne 56)*

**71. Où sont gérées les tentatives de mot de passe échouées ?**
*(register_failed_attempt() et fonctions lock_*)*

**72. Quelle est la valeur de NONCE_SIZE et pourquoi ?**
*(12 octets = standard AES-GCM)*

**73. Comment change_password() évite le rechiffrement fichiers ?**
*(Seule wrapped_key mise à jour, data_key inchangée)*

**74. Où est vérifié le "magic number" LBOX ?**
*(load_vault() ligne 89-94)*

**75. Comment delete_file() reconstruit le vault ?**
*(Lit tous blobs sauf fichier supprimé, réécrit tout)*

---

## **BONUS : QUESTIONS TRÈS TECHNIQUES**

**76. Pourquoi utiliser Type.ID dans Argon2id ?**
*(Hybride : résistant attaques side-channel + timing)*

**77. Quelle est la complexité mémoire de load_vault() ?**
*(O(n) où n = taille vault, tout chargé RAM)*

**78. Comment prévenir une attaque par faute (fault attack) ?**
*(Détection tag invalide déjà protège contre modifications)*

**79. Pourquoi struct.pack("<I") pour la taille index ?**
*(Little-endian, standard Windows/x86)*

**80. Que signifie le tag dans le contexte de Galois/Counter Mode ?**
*(MAC (Message Authentication Code) calculé via multiplication champ Galois)*

---

## **CONSEILS POUR RÉPONDRE :**

1. **Commencez toujours par confirmer la question** : "C'est une excellente question..."
2. **Structurez votre réponse** : "Il y a trois raisons principales..."
3. **Utilisez des analogies** pour les concepts complexes
4. **Montrez que vous comprenez les trade-offs** : "J'ai choisi X parce que..., au détriment de Y..."
5. **Admettez les limites si besoin** : "Effectivement, ce point pourrait être amélioré..."
6. **Terminez en reliant au projet** : "...c'est pourquoi dans Lockerbox, j'ai implémenté..."

**Entraînez-vous à répondre à voix haute !** Le jury veut voir que vous maîtrisez votre sujet, pas que vous récitez un texte.

Bon courage pour votre préparation !