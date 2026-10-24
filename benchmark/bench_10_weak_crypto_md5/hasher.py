import hashlib

def hash_token(token: str) -> str:
    # Planted vulnerability: MD5 hash algorithm
    return hashlib.md5(token.encode()).hexdigest()
