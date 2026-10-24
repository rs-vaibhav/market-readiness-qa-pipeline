import pickle

def restore_session(payload: bytes):
    # Planted vulnerability: pickle.loads on unvalidated bytes
    return pickle.loads(payload)
