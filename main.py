#!/usr/bin/env python3
"""Interface en ligne de commande de LockerBox."""

import logging
import os
import time
from logging.handlers import RotatingFileHandler

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


LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_FILE = os.path.join(LOG_DIR, "lockerbox.log")
os.makedirs(LOG_DIR, exist_ok=True)

logger = logging.getLogger("lockerbox")
logger.setLevel(logging.ERROR)
logger.propagate = False
logger.addHandler(
    RotatingFileHandler(
        LOG_FILE, maxBytes=1_000_000, backupCount=3, encoding="utf-8"
    )
)


def log_error(action, error):
    """Enregistre une erreur sans écrire de mot de passe ni de chemin."""
    logger.error("action=%s error=%s", action, type(error).__name__)


@click.group()
@click.option("--vault", "-v", required=True, help="Chemin vers le fichier vault.")
@click.pass_context
def cli(context, vault):
    """Prepare le vault et le mot de passe pour la commande choisie."""
    if is_locked(vault):
        remaining = max(0, int(locked_until(vault) - time.time()))
        click.echo(f"Verrouillé. Réessayez dans {remaining} secondes.", err=True)
        raise click.exceptions.Exit(1)

    password = click.prompt("Mot de passe maître", hide_input=True)
    context.obj = new_vault(vault, password)


@cli.command()
@click.pass_obj
def create(vault):
    """Cree un fichier vault vide."""
    try:
        if os.path.exists(vault["path"]):
            click.echo("Vault déjà existant.", err=True)
            return
        click.echo("Attention : un mot de passe oublié ne peut pas être récupéré.")
        create_vault(vault)
        click.echo("Vault créé avec succès.")
    except Exception as error:
        log_error("create", error)
        click.echo(f"Erreur lors de la création : {error}", err=True)


@cli.command()
@click.argument("file_path")
@click.pass_obj
def add(vault, file_path):
    """Lit, chiffre et ajoute un fichier au vault."""
    try:
        filename = os.path.basename(file_path)
        if os.path.exists(vault["path"]) and filename in list_files(vault):
            click.echo(f"Le fichier '{filename}' existe déjà et ne peut pas être ajouté.", err=True)
            return
        add_file(vault, file_path)
        click.echo(f"Fichier '{filename}' ajouté.")
    except FileNotFoundError as error:
        log_error("add", error)
        click.echo(f"Fichier source non trouvé : {error}", err=True)
    except LockedError as error:
        log_error("add", error)
        click.echo(f"Verrouillé : {error}", err=True)
    except Exception as error:
        log_error("add", error)
        click.echo(f"Erreur inattendue : {error}", err=True)


@cli.command(name="list-files")
@click.pass_obj
def list_command(vault):
    """Affiche les noms des fichiers presents dans le vault."""
    try:
        files = list_files(vault)
        if not files:
            click.echo("Le vault est vide.")
            return
        for name in files:
            click.echo(name)
    except Exception as error:
        log_error("list", error)
        click.echo(f"Erreur : {error}", err=True)


@cli.command()
@click.argument("filename")
@click.argument("output_path")
@click.pass_obj
def extract(vault, filename, output_path):
    """Dechiffre un fichier du vault vers le disque."""
    try:
        if os.path.exists(output_path):
            click.echo(f"Attention : '{output_path}' existe déjà et sera remplacé.")
        extract_file(vault, filename, output_path)
        click.echo(f"Fichier '{filename}' extrait vers '{output_path}'.")
    except FileNotFoundError as error:
        log_error("extract", error)
        click.echo(f"Fichier non trouvé : {error}", err=True)
    except LockedError as error:
        log_error("extract", error)
        click.echo(f"Verrouillé : {error}", err=True)
    except Exception as error:
        log_error("extract", error)
        click.echo(f"Erreur inattendue : {error}", err=True)


@cli.command()
@click.argument("filename")
@click.pass_obj
def delete(vault, filename):
    """Supprime un fichier du vault."""
    try:
        delete_file(vault, filename)
        click.echo(f"Fichier '{filename}' supprimé.")
    except FileNotFoundError as error:
        log_error("delete", error)
        click.echo(f"Fichier non trouvé : {error}", err=True)
    except LockedError as error:
        log_error("delete", error)
        click.echo(f"Verrouillé : {error}", err=True)
    except Exception as error:
        log_error("delete", error)
        click.echo(f"Erreur inattendue : {error}", err=True)


@cli.command(name="change-password")
@click.option("--new-password", prompt=True, hide_input=True,
              confirmation_prompt=True, help="Nouveau mot de passe maître.")
@click.pass_obj
def change_password(vault, new_password):
    """Remplace le mot de passe du vault."""
    try:
        change_vault_password(vault, new_password)
        click.echo("Mot de passe changé avec succès.")
    except LockedError as error:
        log_error("change-password", error)
        click.echo(f"Verrouillé : {error}", err=True)
    except Exception as error:
        log_error("change-password", error)
        click.echo(f"Erreur inattendue : {error}", err=True)


# Ordre affiche dans l'aide du CLI.
cli.commands = {
    name: cli.commands[name]
    for name in ("create", "change-password", "list-files", "add", "delete", "extract")
}


def command_names(context):
    """Retourne les commandes dans l'ordre choisi pour l'aide."""
    return list(cli.commands)


cli.list_commands = command_names


if __name__ == "__main__":
    cli()
