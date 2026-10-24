def read_user_file(filename: str):
    # Planted vulnerability: unvalidated file path concatenation
    with open(f"/app/storage/{filename}", "r") as f:
        return f.read()
