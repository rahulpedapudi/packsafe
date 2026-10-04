import typer

from ..core.logging_config import setup_logging
from .commands.analyze import app as analyze_app
from .commands.audit import app as audit_app
from .commands.init import app as init_app
from .commands.install import app as install_app

setup_logging()
app = typer.Typer(no_args_is_help=True)


app.add_typer(init_app)
app.add_typer(analyze_app)
app.add_typer(install_app)
app.add_typer(audit_app)

if __name__ == "__main__":
    app()
