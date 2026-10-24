import os

def ping_host(host: str):
    # Planted vulnerability: dynamic command string formatted into os.system
    return os.system(f"ping -c 1 {host}")
