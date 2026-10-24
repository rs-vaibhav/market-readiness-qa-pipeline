def compute_expression(expr: str):
    # Planted vulnerability: dangerous eval
    return eval(expr)
