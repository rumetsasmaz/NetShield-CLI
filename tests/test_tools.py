import hashlib

import pytest

from netshield.modules import hashing, password, portdb


@pytest.mark.parametrize("pw, score", [
    ("", 0), ("abc", 1), ("Abcdefgh1", 4), ("Abcdefg1!", 5), ("abcdefgh", 2), ("ABCDEFG1!", 4),
])
def test_score_password(pw, score):
    assert password.score_password(pw)[0] == score


def test_symbol_check_ignores_letters_and_digits():
    # regression: isalnum used to count letters/digits as symbols
    score, hints = password.score_password("Abcdefgh1")
    assert "Add a symbol" in hints and score == 4


def test_generate_password_properties():
    for length in (8, 16, 40):
        pw = password.generate_password(length)
        assert len(pw) == length
        assert password.score_password(pw)[0] == 5
    assert password.generate_password(20) != password.generate_password(20)
    with pytest.raises(ValueError):
        password.generate_password(7)


@pytest.mark.parametrize("algorithm", hashing.ALGORITHMS)
def test_hash_text_matches_hashlib(algorithm):
    assert hashing.hash_text("hello", algorithm) == hashlib.new(algorithm, b"hello").hexdigest()


@pytest.mark.parametrize("algorithm", hashing.ALGORITHMS)
def test_crack_hash_finds_word_and_detects_algorithm(tmp_path, algorithm):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("alpha\n\nbeta\nsecret\ngamma\n", encoding="utf-8")
    target = hashing.hash_text("secret", algorithm)
    assert hashing.crack_hash(target.upper(), wordlist) == ("secret", 3)
    assert hashing.crack_hash(hashing.hash_text("nope", algorithm), wordlist) == (None, 4)


def test_crack_hash_errors(tmp_path):
    with pytest.raises(ValueError):
        hashing.crack_hash("abc", tmp_path / "x.txt")
    with pytest.raises(FileNotFoundError):
        hashing.crack_hash("a" * 32, tmp_path / "missing.txt")


def test_port_lookup():
    assert portdb.lookup("3389")[0][1] == "rdp"
    assert any(row[0] == 22 for row in portdb.lookup("ssh"))
    assert portdb.lookup("zzz") == [] and portdb.lookup("65000") == []
