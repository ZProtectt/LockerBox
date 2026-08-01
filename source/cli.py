import click
from source.vault import VaultManager
import os

@click.group()
def cli():
    """LockerBox: Coffre-fort numérique sécurisé."""
    pass

@cli.command()
@click.argument('vault_path')
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True)
def init(vault_path, password):
    """Initialise un nouveau vault."""
    try:
        vm = VaultManager(vault_path)
        vm.init_vault(password)
        click.echo(f"Vault '{vault_path}' initialisé.")
    except Exception as e:
        click.echo(f"Erreur: {e}")

@cli.command()
@click.argument('vault_path')
@click.argument('filepath')
@click.option('--password', prompt=True, hide_input=True)
def add(vault_path, filepath, password):
    """Ajoute un fichier au vault."""
    try:
        vm = VaultManager(vault_path)
        vm.add_file(filepath, password)
        click.echo(f"Fichier '{filepath}' ajouté.")
    except Exception as e:
        click.echo(f"Erreur: {e}")

@cli.command()
@click.argument('vault_path')
def list(vault_path):
    """Liste les fichiers."""
    try:
        vm = VaultManager(vault_path)
        files = vm.list_files()
        click.echo("Fichiers dans le vault :")
        if not files:
            click.echo("(Le vault est vide)")
        for f in files:
            click.echo(f"- {f}")
    except Exception as e:
        click.echo(f"Erreur: {e}")

if __name__ == '__main__':
    cli()
