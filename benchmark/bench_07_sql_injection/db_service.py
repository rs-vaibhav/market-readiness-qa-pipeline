def query_user(cursor, username: str):
    # Planted vulnerability: SQL formatted query
    return cursor.execute(f"SELECT * FROM users WHERE username = {username}")
