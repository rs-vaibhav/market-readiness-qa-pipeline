"""Clean string transformation library."""

def slugify(text: str) -> str:
    return text.strip().lower().replace(" ", "-")

def truncate(text: str, max_len: int = 100) -> str:
    return text[:max_len]
