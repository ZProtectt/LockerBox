#!/usr/bin/env python3
"""
SecureVault – Interface CLI pour le coffre-fort chiffré.

Ce module implémente une interface utilisateur en ligne de commande complète
pour gérer des coffres chiffrés (`Vault`). Il utilise la bibliothèque `Click`
pour une expérience utilisateur moderne avec auto‑aide, gestion d'options,
et messages d'erreur clairs (avec émojis).

Le CLI contrôle la sécurité d'en‑tête en vérifiant systématiquement le
verrouillage anti‑bruteforce avant toute interaction avec le coffre.
"""

import click

from source.vault import LockedError, Vault


@click.group()
@click.option("--vault", "-v", required=True, help="Chemin vers le fichier vault.")
@click.pass_context
def cli(ctx, vault: str):
    """
    SecureVault – coffre‑fort chiffré en ligne de commande.
    
    Cette fonction est le point d'entrée de toutes les commandes. Elle :
      1. Vérifie que le coffre n'est pas verrouillé (anti‑bruteforce).
      2. Demande le mot de passe maître de manière sécurisée.
      3. Instancie un objet `Vault` (coffre) et le stocke dans le contexte
         Click pour les sous‑commandes.
         
    Le verrouillage est vérifié AVANT de demander le mot de passe, ce qui
    réduit les canaux auxiliaires et protège contre le déni de service.
    
    Raises:
        SystemExit(1): Si le coffre est temporairement verrouillé.
    """
    # Vérification du verrouillage anti‑bruteforce AVANT de demander le mot de passe.
    # Cette pré‑vérification évite de révéler que le coffre existe ou non.
    temp = Vault(vault, "")
    if temp.is_locked():
        import time
        remaining = int(temp.locked_until - time.time())
        click.echo(
            f"🔒 Verrouillé ! Trop de tentatives. Réessayez dans {remaining} secondes.",
            err=True,
        )
        raise SystemExit(1)

    # Demande sécurisée du mot de passe (masqué à l'écran)
    password = click.prompt("Mot de passe maître", hide_input=True)
    ctx.obj = Vault(vault, password)  # Stockage pour les sous‑commandes


@cli.command()
def create():
    """
    Initialise un nouveau coffre vide (fichier .vault).
    
    Cette commande crée un fichier sur le disque avec :
      - Un sel aléatoire de 16 octets (pour Argon2id).
      - Une clé de données aléatoire de 32 octets (pour AES‑256‑GCM).
      - Un index chiffré vide.
      
    Le coffre créé est immédiatement fonctionnel.
    
    Note:
        Le coffre doit être vide. Si un fichier existe déjà au même emplacement,
        il est écrasé (heureusement, Click protège avec confirmation implicite).
        
    Returns:
        Message de succès via `click.echo`, émoji ✅.
    """
    vault = click.get_current_context().obj
    try:
        vault.create_vault()
        click.echo("✅ Vault créé avec succès.")
    except Exception as e:
        click.echo(f"❌ Erreur lors de la création : {e}", err=True)


@cli.command()
@click.argument("file_path")
def add(file_path: str):
    """
    Ajoute un fichier du système de fichiers dans le coffre.
    
    Le fichier est lu, chiffré avec AES‑256‑GCM, puis ajouté à la fin des
    blobs existants. Le coffre est entièrement ré‑écrit (optimisation future
    possible avec des index retours).
    
    Args:
        file_path: Chemin absolu ou relatif vers le fichier à ajouter.
        
    Raises:
        FileNotFoundError (capturée) : Si le fichier source n'existe pas.
        LockedError (capturée)       : Si le coffre est temporairement verrouillé.
        
    Returns:
        Message de confirmation avec le nom de base du fichier, émoji ✅.
    """
    import os
    vault = click.get_current_context().obj
    try:
        vault.add_file(file_path)
        click.echo(f"✅ Fichier '{os.path.basename(file_path)}' ajouté.")
    except FileNotFoundError as e:
        click.echo(f"❌ Fichier source non trouvé : {e}", err=True)
    except LockedError as e:
        click.echo(f"❌ Verrouillé : {e}", err=True)
    except Exception as e:
        click.echo(f"❌ Erreur inattendue : {e}", err=True)


@cli.command()
def list_files():
    """
    Affiche la liste des fichiers stockés dans le coffre.
    
    Cette commande déchiffre l'index du coffre (ce qui vérifie le mot de passe)
    et affiche les noms des fichiers. Si le coffre est vide, un message adapté
    est montré avec l'émoji 📭.
    
    Raises:
        LockedError (capturée) : Si le coffre est temporairement verrouillé.
        IntegrityError (capturée via Exception) : Si le mot de passe est faux.
        
    Returns:
        Liste formatée des noms de fichiers, ou indication de vide.
    """
    vault = click.get_current_context().obj
    try:
        files = vault.list_files()
        if not files:
            click.echo("📭 Le vault est vide.")
            return
        click.echo("📁 Fichiers dans le vault :")
        for name in files:
            click.echo(f" - {name}")
    except LockedError as e:
        click.echo(f"❌ Verrouillé : {e}", err=True)
    except Exception as e:
        click.echo(f"❌ Erreur inattendue : {e}", err=True)


@cli.command()
@click.argument("filename")
@click.argument("output_path")
def extract(filename: str, output_path: str):
    """
    Extrait un fichier du coffre vers le système de fichiers.
    
    Le fichier est cherché dans l'index du coffre, déchiffré avec vérification
    d'intégrité (tag AES‑GCM) et écrit à l'emplacement spécifié.
    
    Args:
        filename: Nom du fichier dans le coffre (tel que listé par `list_files`).
        output_path: Chemin où écrire le fichier déchiffré.
        
    Raises:
        FileNotFoundError (capturée) : Si le fichier n'existe pas dans le coffre.
        LockedError (capturée)       : Si le coffre est temporairement verrouillé.
        IntegrityError (capturée via Exception) : Si les données sont corrompues.
        
    Returns:
        Message de succès avec noms source et destination, émoji ✅.
    """
    vault = click.get_current_context().obj
    try:
        vault.extract_file(filename, output_path)
        click.echo(f"✅ Fichier '{filename}' extrait vers '{output_path}'.")
    except FileNotFoundError as e:
        click.echo(f"❌ Fichier non trouvé : {e}", err=True)
    except LockedError as e:
        click.echo(f"❌ Verrouillé : {e}", err=True)
    except Exception as e:
        click.echo(f"❌ Erreur inattendue : {e}", err=True)


@cli.command()
@click.argument("filename")
def delete(filename: str):
    """
    Supprime un fichier du coffre sans rechiffrer les autres.
    
    Cette commande ré‑écrit entièrement le fichier vault en excluant le
    blob du fichier à supprimer. Les offsets des fichiers restants sont
    recalculés et l'index est mis à jour.
    
    Args:
        filename: Nom du fichier à supprimer (doit exister dans le coffre).
        
    Raises:
        FileNotFoundError (capturée) : Si le fichier n'existe pas dans le coffre.
        LockedError (capturée)       : Si le coffre est temporairement verrouillé.
        
    Returns:
        Message de confirmation avec émoji 🗑️.
    """
    vault = click.get_current_context().obj
    try:
        vault.delete_file(filename)
        click.echo(f"🗑️  Fichier '{filename}' supprimé.")
    except FileNotFoundError as e:
        click.echo(f"❌ Fichier non trouvé : {e}", err=True)
    except LockedError as e:
        click.echo(f"❌ Verrouillé : {e}", err=True)
    except Exception as e:
        click.echo(f"❌ Erreur inattendue : {e}", err=True)


@cli.command(name="change-password")
@click.option("--new-password", prompt=True, hide_input=True, confirmation_prompt=True,
              help="Nouveau mot de passe maître.")
def change_password(new_password: str):
    """
    Change le mot de passe maître sans rechiffrer les fichiers.
    
    Cette opération exploite l'architecture à deux clés du coffre :
      - La clé de données (`key`) reste inchangée.
      - Seule la wrapped_key (enveloppe chiffrée) est rechiffrée avec la
        nouvelle clé dérivée du nouveau mot de passe.
        
    Le sel est régénéré (bonne pratique cryptographique). L'opération est
    rapide quelle que soit la taille des fichiers stockés.
    
    Raises:
        ValueError (capturée implicitement) : Si le nouveau mot de passe est invalide.
        LockedError (capturée) : Si le coffre est temporairement verrouillé.
        
    Returns:
        Message de succès avec émoji 🔑.
    """
    vault = click.get_current_context().obj
    try:
        vault.change_password(new_password)
        click.echo("🔑 Mot de passe changé avec succès.")
    except LockedError as e:
        click.echo(f"❌ Verrouillé : {e}", err=True)
    except Exception as e:
        click.echo(f"❌ Erreur inattendue : {e}", err=True)


if __name__ == "__main__":
    cli()
