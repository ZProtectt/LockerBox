#!/usr/bin/env python3

import os
import time
import click

from source.vault import (
    LockedError,
    add_file,
    change_password as change_vault_password,
    create_vault,
    delete_file,
    extract_file,
    is_locked,
    list_files,
    locked_until,
    new_vault,
)


@click.group()
@click.option("-v", "vault", required=True, help="Chemin vers le fichier vault.")
@click.pass_context
def cli(context, vault):
    # Initialise le contexte avec le chemin du vault et la clé dérivée du mot de passe.
    if is_locked(vault):
        remaining = max(0, int(locked_until(vault) - time.time()))
        click.echo(f"Verrouillé. Réessayez dans {remaining} secondes.", err=True)
        raise click.exceptions.Exit(1)

    password = click.prompt("Entrez le mot de passe maître", hide_input=True)
    context.obj = new_vault(vault, password)


@cli.command()
@click.pass_obj
def create(vault):
    """Crée un fichier vault."""
    # Vérifie si le vault existe déjà et crée un nouveau vault vide avec un sel et une clé de données aléatoires.
    try:
        if os.path.exists(vault["path"]):
            click.echo("Vault déjà existant.", err=True)
            return
        click.echo("Attention : un mot de passe oublié ne peut pas être récupéré.")
        create_vault(vault)
        click.echo("Vault créé avec succès.")
    except Exception as error:
        click.echo(f"Erreur lors de la création : {error}", err=True)


@cli.command()
@click.argument("file_path")
@click.pass_obj
def add(vault, file_path):
    """Ajoute un fichier dans le vault."""
    # Vérifie si le fichier existe déjà dans le vault et ajoute le fichier spécifié.
    try:
        filename = os.path.basename(file_path)
        if os.path.exists(vault["path"]) and filename in list_files(vault):
            click.echo(f"Le fichier '{filename}' existe déjà et ne peut pas être ajouté.", err=True)
            return
        add_file(vault, file_path)
        click.echo(f"Fichier '{filename}' ajouté.")
    except FileNotFoundError as error:
        click.echo(f"Fichier source non trouvé : {error}", err=True)
    except LockedError as error:
        click.echo(f"Verrouillé : {error}", err=True)
    except Exception as error:
        click.echo(f"Erreur inattendue : {error}", err=True)


@cli.command(name="list-files")
@click.pass_obj
def list_command(vault):
    """Affiche la liste des fichiers presents dans le vault."""
    # Vérifie si le vault est vide et affiche les noms des fichiers stockés dans le vault.
    try:
        files = list_files(vault)
        if not files:
            click.echo("Le vault est vide.")
            return
        for name in files:
            click.echo(name)
    except Exception as error:
        click.echo(f"Erreur : {error}", err=True)


@cli.command()
@click.argument("filename")
@click.argument("output_path")
@click.pass_obj
def extract(vault, filename, output_path):
    """Exporte un fichier du vault vers la destination souhaitée."""
    # Vérifie si le fichier existe dans le vault et extrait le fichier spécifié vers l'emplacement demandé.
    try:
        if os.path.exists(output_path):
            click.echo(f"Attention : '{output_path}' existe déjà et sera remplacé.")
        extract_file(vault, filename, output_path)
        click.echo(f"Fichier '{filename}' extrait vers '{output_path}'.")
    except FileNotFoundError as error:
        click.echo(f"Fichier non trouvé : {error}", err=True)
    except LockedError as error:
        click.echo(f"Verrouillé : {error}", err=True)
    except Exception as error:
        click.echo(f"Erreur inattendue : {error}", err=True)


@cli.command()
@click.argument("filename")
@click.pass_obj
def delete(vault, filename):
    """Supprime un fichier du vault"""
    # Vérifie si le fichier existe dans le vault et supprime le fichier spécifié.
    try:
        delete_file(vault, filename)
        click.echo(f"Fichier '{filename}' supprimé.")
    except FileNotFoundError as error:
        click.echo(f"Fichier non trouvé : {error}", err=True)
    except LockedError as error:
        click.echo(f"Verrouillé : {error}", err=True)
    except Exception as error:
        click.echo(f"Erreur inattendue : {error}", err=True)


@cli.command(name="change-password")
@click.option("--new-password", prompt=True, hide_input=True, confirmation_prompt=True, help="Nouveau mot de passe maître.")
@click.pass_obj
def change_password(vault, new_password):
    """Change le mot de passe actuel du vault."""
    # Vérifie si le vault est verrouillé et change le mot de passe maître du vault.
    try:
        change_vault_password(vault, new_password)
        click.echo("Mot de passe changé avec succès.")
    except LockedError as error:
        click.echo(f"Verrouillé : {error}", err=True)
    except Exception as error:
        click.echo(f"Erreur inattendue : {error}", err=True)

if __name__ == "__main__":
    # Lance l'interface en ligne de commande (CLI) pour LockerBox.
    cli()
