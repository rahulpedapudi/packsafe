import typer

app = typer.Typer()

@app.command()
def audit():
    print("Auditing Folder...")