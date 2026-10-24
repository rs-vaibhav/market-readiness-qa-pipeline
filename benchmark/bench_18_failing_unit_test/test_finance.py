from finance import compute_tax

def test_compute_tax_positive():
    assert compute_tax(100.0) == 20.0
