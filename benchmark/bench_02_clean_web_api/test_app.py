from app import get_status

def test_get_status():
    res = get_status()
    assert res["status"] == "healthy"
