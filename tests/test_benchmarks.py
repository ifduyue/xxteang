import os

import xxteang


KEY = os.urandom(16)
DATA_SMALL = os.urandom(64)
DATA_MEDIUM = os.urandom(1000)
DATA_LARGE = os.urandom(10000)
DATA_HUGE = os.urandom(1024 * 1024 * 2)

ENC_SMALL = xxteang.encrypt(DATA_SMALL, KEY)
ENC_MEDIUM = xxteang.encrypt(DATA_MEDIUM, KEY)
ENC_LARGE = xxteang.encrypt(DATA_LARGE, KEY)
ENC_HUGE = xxteang.encrypt(DATA_HUGE, KEY)

HEXENC_MEDIUM = xxteang.encrypt_hex(DATA_MEDIUM, KEY)
HEXENC_HUGE = xxteang.encrypt_hex(DATA_HUGE, KEY)

CIPHER = xxteang.XXTEA(KEY)

CIPHER_HEXENC_MEDIUM = CIPHER.encrypt_hex(DATA_MEDIUM)
CIPHER_HEXENC_HUGE = CIPHER.encrypt_hex(DATA_HUGE)


def test_encrypt_small(benchmark):
    benchmark(xxteang.encrypt, DATA_SMALL, KEY)


def test_encrypt_medium(benchmark):
    benchmark(xxteang.encrypt, DATA_MEDIUM, KEY)


def test_encrypt_large(benchmark):
    benchmark(xxteang.encrypt, DATA_LARGE, KEY)


def test_decrypt_small(benchmark):
    benchmark(xxteang.decrypt, ENC_SMALL, KEY)


def test_decrypt_medium(benchmark):
    benchmark(xxteang.decrypt, ENC_MEDIUM, KEY)


def test_decrypt_large(benchmark):
    benchmark(xxteang.decrypt, ENC_LARGE, KEY)


def test_encrypt_hex(benchmark):
    benchmark(xxteang.encrypt_hex, DATA_MEDIUM, KEY)


def test_decrypt_hex(benchmark):
    benchmark(xxteang.decrypt_hex, HEXENC_MEDIUM, KEY)


def test_encrypt_huge(benchmark):
    benchmark(xxteang.encrypt, DATA_HUGE, KEY)


def test_decrypt_huge(benchmark):
    benchmark(xxteang.decrypt, ENC_HUGE, KEY)


def test_encrypt_hex_huge(benchmark):
    benchmark(xxteang.encrypt_hex, DATA_HUGE, KEY)


def test_decrypt_hex_huge(benchmark):
    benchmark(xxteang.decrypt_hex, HEXENC_HUGE, KEY)


# ── XXTEA type ──────────────────────────────────────────────────────────

def test_type_encrypt_small(benchmark):
    benchmark(CIPHER.encrypt, DATA_SMALL)


def test_type_encrypt_medium(benchmark):
    benchmark(CIPHER.encrypt, DATA_MEDIUM)


def test_type_encrypt_large(benchmark):
    benchmark(CIPHER.encrypt, DATA_LARGE)


def test_type_decrypt_small(benchmark):
    benchmark(CIPHER.decrypt, ENC_SMALL)


def test_type_decrypt_medium(benchmark):
    benchmark(CIPHER.decrypt, ENC_MEDIUM)


def test_type_decrypt_large(benchmark):
    benchmark(CIPHER.decrypt, ENC_LARGE)


def test_type_encrypt_huge(benchmark):
    benchmark(CIPHER.encrypt, DATA_HUGE)


def test_type_decrypt_huge(benchmark):
    benchmark(CIPHER.decrypt, ENC_HUGE)


def test_type_encrypt_hex_medium(benchmark):
    benchmark(CIPHER.encrypt_hex, DATA_MEDIUM)


def test_type_decrypt_hex_medium(benchmark):
    benchmark(CIPHER.decrypt_hex, CIPHER_HEXENC_MEDIUM)


def test_type_encrypt_hex_huge(benchmark):
    benchmark(CIPHER.encrypt_hex, DATA_HUGE)


def test_type_decrypt_hex_huge(benchmark):
    benchmark(CIPHER.decrypt_hex, CIPHER_HEXENC_HUGE)
