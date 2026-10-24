"""Clean API service."""
from typing import Dict

def get_status() -> Dict[str, str]:
    return {"status": "healthy", "service": "api"}
