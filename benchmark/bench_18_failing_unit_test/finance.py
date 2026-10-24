def compute_tax(amount: float) -> float:
    # Planted bug: negative tax calculation
    return -amount * 0.2
