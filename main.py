import click

from source.vault import Vault


@click.group()
@click.option("--vault", "-v", required=True, help="Chemin vers le fichier vault.")
@click.option("--password", "-p", prompt=True, hide_input=True, help="Mot de passe maître.")
@click.pass_context
def cli(ctx, vault, password):
    """SecureVault – coffre-fort chiffré en ligne de commande."""
    ctx.obj = Vault(vault, password)


@cli.command()
def create():
    """Initialise un nouveau vault."""
    vault = click.get_current_context().obj
    vault.create_vault()
    click.echo("Vault créé avec succès.")


@cli.command()
@click.argument("file_path")
def add(file_path):
    """Ajoute un fichier dans le vault."""
    import os
    vault = click.get_current_context().obj
    vault.add_file(file_path)
    click.echo(f"Fichier '{os.path.basename(file_path)}' ajouté.")


@cli.command()
def list_files():
    """Liste les fichiers dans le vault."""
    vault = click.get_current_context().obj
    files = vault.list_files()
    if not files:
        click.echo("Le vault est vide.")
        return
    click.echo("Fichiers dans le vault :")
    for name in files:
        click.echo(f" - {name}")


@cli.command()
@click.argument("filename")
@click.argument("output_path")
def extract(filename, output_path):
    """Extrait un fichier depuis le vault."""
    vault = click.get_current_context().obj
    vault.extract_file(filename, output_path)
    click.echo(f"Fichier '{filename}' extrait vers '{output_path}'.")


@cli.command()
@click.argument("filename")
def delete(filename):
    """Supprime un fichier du vault."""
    vault = click.get_current_context().obj
    vault.delete_file(filename)
    click.echo(f"Fichier '{filename}' supprimé.")


@cli.command(name="change-password")
@click.option("--new-password", prompt=True, hide_input=True, confirmation_prompt=True,
              help="Nouveau mot de passe maître.")
def change_password(new_password):
    """Change le mot de passe sans rechiffrer les fichiers."""
    vault = click.get_current_context().obj
    vault.change_password(new_password)
    click.echo("Mot de passe changé avec succès.")


if __name__ == "__main__":
    cli()
