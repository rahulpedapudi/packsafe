from typing import Annotated

import typer

app = typer.Typer()


@app.command()
def install(
    package_name: Annotated[
        str, typer.Argument(help="Name of the package to be installed")
    ],
    # explain: Annotated[bool, typer.Option(False, help="Let AI explain")],
):

    # exisitence of the package
    # typosquatting
    # slopsquatting
    # fetch the data:
    # pypi
    # osv
    # github
    # ...
    # calculate score
    # score engine should do the work
    # install or block
    # llm inference if flag is enabled --explain

    print(f"Installing Package - {package_name}")
