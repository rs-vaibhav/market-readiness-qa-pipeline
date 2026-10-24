from text_utils import slugify, truncate

def test_slugify():
    assert slugify("Hello World") == "hello-world"

def test_truncate():
    assert len(truncate("abcdefgh", 4)) == 4
