"""Tests for the educational cryptography logic (no GUI required)."""
from collections import Counter

import pytest

from modules.credentials.crypto_logic import (
    CRYPTO_QUIZ_BANK,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    base64_decode,
    base64_encode,
    caesar,
    caesar_break,
    crypto_choices,
    derive_key,
    hash_with_salt,
    rsa_decrypt,
    rsa_encrypt,
    rsa_generate_keypair,
    sha256_hex,
    verify_crypto_quiz_bank,
    verify_salted_hash,
    vigenere,
)


def test_caesar_known_vectors_and_round_trip():
    assert caesar("CAT", 3) == "FDW"
    assert caesar("FDW", 3, decrypt=True) == "CAT"
    assert caesar("Hello, World!", 5) == "Mjqqt, Btwqi!"
    assert caesar("Mjqqt, Btwqi!", 5, decrypt=True) == "Hello, World!"
    assert caesar("XYZ", 3) == "ABC"  # wraps around
    assert caesar("abc", 26) == "abc"  # full cycle


def test_caesar_rejects_bad_shift():
    with pytest.raises(ValueError):
        caesar("CAT", "three")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        caesar("CAT", 3.5)  # type: ignore[arg-type]


def test_vigenere_known_vector_and_round_trip():
    assert vigenere("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"
    assert vigenere("LXFOPVEFRNHR", "LEMON", decrypt=True) == "ATTACKATDAWN"
    assert vigenere("Attack at dawn!", "lemon") == "Lxfopv ef rnhr!"
    assert vigenere("Lxfopv ef rnhr!", "lemon", decrypt=True) == "Attack at dawn!"


def test_vigenere_rejects_empty_key():
    with pytest.raises(ValueError):
        vigenere("HELLO", "123")


def test_base64_round_trip_and_invalid():
    assert base64_encode("Hello, world!") == "SGVsbG8sIHdvcmxkIQ=="
    assert base64_decode("SGVsbG8sIHdvcmxkIQ==") == "Hello, world!"
    assert base64_decode(base64_encode("Maxim © 2026")) == "Maxim © 2026"
    with pytest.raises(ValueError):
        base64_decode("!!!not base64!!!")


def test_sha256_known_vector():
    assert sha256_hex("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )


def test_derive_key_produces_32_bytes_and_varies_with_salt():
    salt = b"fixed-salt-123456"
    key = derive_key("correct horse battery staple", salt)
    assert len(key) == 32
    other = derive_key("correct horse battery staple", b"another-salt-1234")
    assert key != other


def test_aes_gcm_round_trip():
    salt, nonce, ciphertext = aes_gcm_encrypt("hunter2", "Top secret message.")
    assert aes_gcm_decrypt("hunter2", salt, nonce, ciphertext) == "Top secret message."


def test_aes_gcm_wrong_passphrase_fails():
    salt, nonce, ciphertext = aes_gcm_encrypt("correct", "secret")
    with pytest.raises(ValueError, match="passphrase is wrong or the data was modified"):
        aes_gcm_decrypt("wrong", salt, nonce, ciphertext)


def test_aes_gcm_tampered_ciphertext_fails():
    salt, nonce, ciphertext = aes_gcm_encrypt("correct", "secret")
    tampered = bytearray(ciphertext)
    tampered[0] ^= 0x01
    with pytest.raises(ValueError, match="passphrase is wrong or the data was modified"):
        aes_gcm_decrypt("correct", salt, nonce, bytes(tampered))


def test_aes_gcm_empty_message_rejected():
    with pytest.raises(ValueError):
        aes_gcm_encrypt("correct", "")


def test_crypto_quiz_bank_structure_and_verification():
    verify_crypto_quiz_bank()
    assert len(CRYPTO_QUIZ_BANK) == 80
    assert {q.identifier for q in CRYPTO_QUIZ_BANK} == set(range(1, 81))
    counts = Counter(q.category for q in CRYPTO_QUIZ_BANK)
    assert len(counts) == 8 and all(count == 10 for count in counts.values())
    assert all(q.explanation for q in CRYPTO_QUIZ_BANK)


def test_crypto_quiz_choices_four_distinct_for_every_question():
    import random
    for question in CRYPTO_QUIZ_BANK:
        options = crypto_choices(question.correct_answer, rng=random.Random(question.identifier))
        assert len(options) == 4 and len(set(options)) == 4
        assert question.correct_answer in options


def test_caesar_break_tries_all_25_shifts_and_finds_plaintext():
    results = caesar_break("FDW")
    assert len(results) == 25
    assert all(1 <= shift <= 25 for shift, _ in results)
    assert (23, "CAT") in results  # shift 23 == decrypt by 3
    assert len({result for _, result in results}) == 25  # all distinct


def test_salted_hashing_same_password_different_salts():
    salt1, hash1 = hash_with_salt("hunter2")
    salt2, hash2 = hash_with_salt("hunter2")
    assert salt1 != salt2 and hash1 != hash2
    # Deterministic for a fixed salt
    again_salt, again_hash = hash_with_salt("hunter2", salt1)
    assert again_salt == salt1 and again_hash == hash1


def test_salted_hashing_verify():
    salt, digest = hash_with_salt("correct horse")
    assert verify_salted_hash("correct horse", salt, digest) is True
    assert verify_salted_hash("wrong horse", salt, digest) is False
    assert verify_salted_hash("correct horse", "00" * 16, digest) is False
    with pytest.raises(ValueError):
        hash_with_salt("")


def test_rsa_keypair_round_trip():
    private_pem, public_pem = rsa_generate_keypair()
    ciphertext = rsa_encrypt(public_pem, "Secret RSA message")
    assert rsa_decrypt(private_pem, ciphertext) == "Secret RSA message"


def test_rsa_wrong_private_key_fails():
    private_pem, public_pem = rsa_generate_keypair()
    other_private, _ = rsa_generate_keypair()
    ciphertext = rsa_encrypt(public_pem, "Secret")
    with pytest.raises(ValueError, match="wrong private key or corrupted"):
        rsa_decrypt(other_private, ciphertext)
