import typer

from .commands.analyze import app as analyze_app
from .commands.audit import app as audit_app
from .commands.install import app as install_app

app = typer.Typer(no_args_is_help=True)

app.add_typer(analyze_app)
app.add_typer(install_app)
app.add_typer(audit_app)

if __name__ == "__main__":
    app()
