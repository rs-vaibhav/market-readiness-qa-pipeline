from math_ops import add, sub, mul, div

def test_add_ok():
    assert add(10, 5) == 15

def test_sub_ok():
    assert sub(10, 5) == 5

def test_mul_ok():
    assert mul(10, 5) == 50

def test_div_fails():
    assert div(10, 5) == 2  # Fails!
