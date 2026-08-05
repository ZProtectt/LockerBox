import click
import os
from vault import Vault

@click.group()
@click.option('--vault', '-v', required=True, help="Chemin vers le fichier vault.")
@click.option('--password', '-p', prompt=True, hide_input=True, help="Mot de passe maître.")
@click.pass_context
def cli(ctx, vault, password):
    ctx.obj = Vault(vault, password)

@cli.command()
@click.pass_obj
def create(vault):
    """Initialise un nouveau vault."""
    vault.create_vault()
    click.echo("Vault créé avec succès.")

@cli.command()
@click.argument('file_path')
@click.pass_obj
def add(vault, file_path):
    """Ajoute un fichier au vault."""
    vault.load_vault()
    vault.add_file(file_path)
    click.echo(f"Fichier '{os.path.basename(file_path)}' ajouté.")

@cli.command()
@click.pass_obj
def list(vault):
    """Liste les fichiers dans le vault."""
    vault.load_vault()
    files = vault.list_files()
    if not files:
        click.echo("Le vault est vide.")
    else:
        click.echo("Fichiers dans le vault :")
        for f in files:
            click.echo(f" - {f}")

@cli.command()
@click.argument('filename')
@click.argument('output_path')
@click.pass_obj
def extract(vault, filename, output_path):
    """Extrait un fichier du vault."""
    vault.load_vault()
    vault.extract_file(filename, output_path)
    click.echo(f"Fichier '{filename}' extrait vers '{output_path}'.")

if __name__ == "__main__":
    cli()
