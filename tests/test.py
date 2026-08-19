import os
import binascii
import ctypes
import sys

import unittest
import xxteang


class TestXXTEA(unittest.TestCase):
    data = b'How do you do?'
    key = b'Fine. And you?  '
    enc = b'x\xf4e\xeb\x1bI\x85\x88}\x11\x84.\xde\x856!'
    hexenc = b'78f465eb1b4985887d11842ede853621'

    def test_version(self):
        version = xxteang.VERSION
        self.assertEqual(True, isinstance(version, str))

    def test_encrypt(self):
        enc = xxteang.encrypt(self.data, self.key)
        self.assertEqual(enc, self.enc)

    def test_encrypt_hex(self):
        hexenc = xxteang.encrypt_hex(self.data, self.key)
        self.assertEqual(hexenc, self.hexenc)

    def test_decrypt(self):
        data = xxteang.decrypt(self.enc, self.key)
        self.assertEqual(data, self.data)

    def test_decrypt_hex(self):
        data = xxteang.decrypt_hex(self.hexenc, self.key)
        self.assertEqual(data, self.data)

    def test_urandom(self):
        for i in range(2048):
            key = os.urandom(16)
            data = os.urandom(i)

            enc = xxteang.encrypt(data, key)
            dec = xxteang.decrypt(enc, key)
            self.assertEqual(data, dec)

    def test_zero_bytes(self):
        for i in range(2048):
            data = b'\0' * i
            key = os.urandom(16)
            enc = xxteang.encrypt(data, key)
            dec = xxteang.decrypt(enc, key)
            self.assertEqual(data, dec)

            key = b'\0' * 16
            enc = xxteang.encrypt(data, key)
            dec = xxteang.decrypt(enc, key)
            self.assertEqual(data, dec)

    def test_encrypt_nopadding(self):
        key = os.urandom(16)
        for i in (8, 12, 16, 20):
            data = os.urandom(i)
            enc = xxteang.encrypt(data, key, padding=False)
            dec = xxteang.decrypt(enc, key, padding=False)
            self.assertEqual(data, dec)

    def test_encrypt_hex_nopadding(self):
        key = os.urandom(16)
        for i in (8, 12, 16, 20):
            data = os.urandom(i)
            enc = xxteang.encrypt_hex(data, key, padding=False)
            dec = xxteang.decrypt_hex(enc, key, padding=False)
            self.assertEqual(data, dec)

    def test_encrypt_nopadding_zero(self):
        key = os.urandom(16)
        for i in (8, 12, 16, 20):
            data = b'\0' * i
            enc = xxteang.encrypt(data, key, padding=False)
            dec = xxteang.decrypt(enc, key, padding=False)
            self.assertEqual(data, dec)

    def test_encrypt_hex_nopadding_zero(self):
        key = os.urandom(16)
        for i in (8, 12, 16, 20):
            data = b'\0' * i
            enc = xxteang.encrypt_hex(data, key, padding=False)
            dec = xxteang.decrypt_hex(enc, key, padding=False)
            self.assertEqual(data, dec)

    # ── short input / 4-byte / 8-byte edge cases (8-byte PKCS#7) ──

    def test_encrypt_decrypt_4byte_edge(self):
        """4-byte data: all 256 last-byte values round-trip correctly.

        The 8-byte PKCS#7 adds 4 pad bytes (pad=4) to reach the 8-byte
        block, and the unpadding must work regardless of the plaintext's
        last byte value."""
        key = os.urandom(16)
        for last in range(256):
            data = b'\x00\x00\x00' + bytes([last])
            enc = xxteang.encrypt(data, key)
            dec = xxteang.decrypt(enc, key)
            self.assertEqual(data, dec,
                             f'4-byte edge failed at last={last}')

    def test_encrypt_decrypt_8byte_edge(self):
        """8-byte data: a multiple of the 8-byte padding block.

        The 8-byte PKCS#7 adds a full block of padding (8 bytes of
        value 8) even when data is already a multiple of 8 bytes."""
        key = os.urandom(16)
        for last in range(256):
            data = b'\x00' * 7 + bytes([last])
            enc = xxteang.encrypt(data, key)
            dec = xxteang.decrypt(enc, key)
            self.assertEqual(data, dec,
                             f'8-byte edge failed at last={last}')

    def test_encrypt_decrypt_short_inputs(self):
        """Inputs < 8 bytes are padded to exactly 8 bytes (pad 1-8)."""
        key = os.urandom(16)
        for length in range(8):
            data = os.urandom(length)
            enc = xxteang.encrypt(data, key)
            dec = xxteang.decrypt(enc, key)
            self.assertEqual(data, dec,
                             f'short input length={length} failed')

    def test_encrypt_decrypt_all_short_lengths(self):
        """Systematic round-trip for every length 0..16, 8 variants each."""
        key = os.urandom(16)
        for length in range(17):
            for _ in range(8):
                data = os.urandom(length)
                enc = xxteang.encrypt(data, key)
                dec = xxteang.decrypt(enc, key)
                self.assertEqual(data, dec,
                                 f'length={length} failed')

    def test_hex_encode(self):
        for i in range(2048):
            key = os.urandom(16)
            data = os.urandom(i)

            enc = xxteang.encrypt(data, key)
            hexenc = xxteang.encrypt_hex(data, key)
            self.assertEqual(binascii.b2a_hex(enc), hexenc)

    def test_decrypt_invalid(self):
        """Invalid padding is rejected deterministically.

        Encrypt with padding=False a plaintext whose last bytes are a
        known-bad pad value, then decrypt with padding=True: the round-
        trip restores the exact plaintext, so the padding check sees
        precisely the crafted value.  (Random data would only fail with
        probability ~1/256, since XXTEA is a permutation and a random
        plaintext's last byte is a plausible pad value that often.)"""
        key = os.urandom(16)
        data = bytearray(os.urandom(32))

        # pad = 0: never a legal PKCS#7 pad value
        data[-1] = 0x00
        enc = xxteang.encrypt(bytes(data), key, padding=False)
        with self.assertRaises(ValueError):
            xxteang.decrypt(enc, key)

        # pad = 9: larger than the 8-byte block
        data[-1] = 0x09
        enc = xxteang.encrypt(bytes(data), key, padding=False)
        with self.assertRaises(ValueError):
            xxteang.decrypt(enc, key)

        # pad = 2 but the byte before it is not 0x02
        data[-2], data[-1] = 0x00, 0x02
        enc = xxteang.encrypt(bytes(data), key, padding=False)
        with self.assertRaises(ValueError):
            xxteang.decrypt(enc, key)

        # padding=False: no integrity check, decrypt succeeds; only the
        # ciphertext length requirement (>= 8 bytes, multiple of 4) raises
        enc = xxteang.encrypt(os.urandom(32), key, padding=False)
        xxteang.decrypt(enc, key, padding=False)
        for length in (0, 1, 4, 6, 7, 9):
            with self.assertRaises(ValueError):
                xxteang.decrypt(os.urandom(length), key, padding=False)


class TestLargeData(unittest.TestCase):
    """Verify encrypt/decrypt with large data doesn't overflow."""

    LARGE_SIZE = 100 * 1024 * 1024  # 100 MB

    def test_large_data_roundtrip(self):
        try:
            data = b'\x00' * self.LARGE_SIZE
        except MemoryError:
            self.skipTest('insufficient memory for large buffer')

        key = os.urandom(16)
        enc = xxteang.encrypt(data, key)
        dec = xxteang.decrypt(enc, key)
        self.assertEqual(len(dec), len(data))
        self.assertEqual(dec, data)

    def test_large_data_nopadding_roundtrip(self):
        try:
            data = b'\x00' * self.LARGE_SIZE
        except MemoryError:
            self.skipTest('insufficient memory for large buffer')

        key = os.urandom(16)
        enc = xxteang.encrypt(data, key, padding=False)
        dec = xxteang.decrypt(enc, key, padding=False)
        self.assertEqual(len(dec), len(data))
        self.assertEqual(dec, data)


class TestSizeOverflow(unittest.TestCase):
    """Overflow guards on output sizing, without committing RAM for the payload.

    ctypes exports a contiguous buffer of the requested length backed by a
    single byte.  _encrypt_impl / _decrypt_impl check data_len before reading
    the input or allocating the ciphertext, so the backing byte is never
    indexed.  Do not test the just-under-limit path: that would still try to
    allocate ~8 GiB (64-bit) or ~2 GiB (32-bit) of output.
    """

    @staticmethod
    def _buffer(nbytes):
        try:
            backing = ctypes.c_char()
            buf = (ctypes.c_char * nbytes).from_address(ctypes.addressof(backing))
        except (OverflowError, MemoryError, ValueError, TypeError) as e:
            raise unittest.SkipTest(
                'cannot construct %d-byte buffer view: %s' % (nbytes, e))
        buf._keepalive = backing
        return buf

    def test_btea_word_count_overflow(self):
        """out_size/4 > INT_MAX is reachable when Py_ssize_t is 64-bit (~8 GiB)."""
        if sys.maxsize <= 2 ** 32:
            self.skipTest('32-bit: word count cannot exceed INT_MAX')

        int_max = 2 ** (ctypes.sizeof(ctypes.c_int) * 8 - 1) - 1
        too_big = (int_max + 1) * 4
        buf = self._buffer(too_big)
        key = os.urandom(16)

        with self.assertRaises(OverflowError) as cm:
            xxteang.encrypt(buf, key)
        self.assertIn('data too large', str(cm.exception))
        with self.assertRaises(OverflowError):
            xxteang.encrypt(buf, key, padding=False)
        with self.assertRaises(OverflowError):
            xxteang.encrypt_hex(buf, key)
        with self.assertRaises(OverflowError):
            xxteang.decrypt(buf, key)
        with self.assertRaises(OverflowError):
            xxteang.XXTEA(key).encrypt(buf)

    def test_padded_encrypt_overflow_at_int_max_words(self):
        """Padding pushes a just-under-8GiB input over the btea word-count limit."""
        if sys.maxsize <= 2 ** 32:
            self.skipTest('32-bit: word count cannot exceed INT_MAX')

        int_max = 2 ** (ctypes.sizeof(ctypes.c_int) * 8 - 1) - 1
        # out_size = (len & ~7) + 8; this is the smallest len with out_size/4 > INT_MAX
        too_big = (int_max + 1) * 4 - 8
        buf = self._buffer(too_big)
        key = os.urandom(16)

        with self.assertRaises(OverflowError) as cm:
            xxteang.encrypt(buf, key)
        self.assertIn('data too large', str(cm.exception))
        # padding=False still fits in INT_MAX words and would allocate ~8 GiB.

    def test_padded_size_overflow_32bit(self):
        """data_len > PY_SSIZE_T_MAX - 8 is only reachable on 32-bit Py_ssize_t."""
        if sys.maxsize > 2 ** 32:
            self.skipTest('64-bit: PY_SSIZE_T_MAX - 8 is not reachable')

        buf = self._buffer(sys.maxsize - 7)
        key = os.urandom(16)

        with self.assertRaises(OverflowError) as cm:
            xxteang.encrypt(buf, key)
        self.assertIn('data too large', str(cm.exception))
        with self.assertRaises(OverflowError):
            xxteang.encrypt_hex(buf, key)
        with self.assertRaises(OverflowError):
            xxteang.XXTEA(key).encrypt(buf)


class TestArgPassing(unittest.TestCase):
    """Test all parameter passing combinations for encrypt/decrypt/encrypt_hex/decrypt_hex."""

    @classmethod
    def setUpClass(cls):
        cls.key = os.urandom(16)
        cls.data = os.urandom(32)
        cls.enc = xxteang.encrypt(cls.data, cls.key)
        cls.hexenc = xxteang.encrypt_hex(cls.data, cls.key)

    # ── helpers ──────────────────────────────────────────────────────────

    @staticmethod
    def _rounds_from_args(args, kwargs):
        """Extract rounds from positional or keyword args."""
        if 'rounds' in kwargs:
            return kwargs['rounds']
        # rounds is the 4th positional arg (index 3)
        if len(args) > 3:
            return args[3]
        return 0

    def _try_encrypt(self, *args, **kwargs):
        """Call encrypt and verify by decrypting with the same key+rounds."""
        rounds = self._rounds_from_args(args, kwargs)
        enc = xxteang.encrypt(*args, **kwargs)
        dec = xxteang.decrypt(enc, self.key, rounds=rounds)
        self.assertEqual(dec, self.data)
        return enc

    def _try_decrypt(self, *args, **kwargs):
        """Call decrypt and verify result.
        Re-encrypts self.data with the same parameters first so rounds match."""
        rounds = self._rounds_from_args(args, kwargs)
        padding = kwargs.get('padding', True)
        enc = xxteang.encrypt(self.data, self.key, padding=padding, rounds=rounds)
        dec = xxteang.decrypt(enc, *args[1:], **{k: v for k, v in kwargs.items() if k != 'data'})
        self.assertEqual(dec, self.data)

    def _try_encrypt_hex(self, *args, **kwargs):
        """Call encrypt_hex and verify by decrypting with the same key+rounds."""
        rounds = self._rounds_from_args(args, kwargs)
        hexenc = xxteang.encrypt_hex(*args, **kwargs)
        dec = xxteang.decrypt_hex(hexenc, self.key, rounds=rounds)
        self.assertEqual(dec, self.data)

    def _try_decrypt_hex(self, *args, **kwargs):
        """Call decrypt_hex and verify result.
        Re-encrypts self.data with the same parameters first so rounds match."""
        rounds = self._rounds_from_args(args, kwargs)
        padding = kwargs.get('padding', True)
        hexenc = xxteang.encrypt_hex(self.data, self.key, padding=padding, rounds=rounds)
        dec = xxteang.decrypt_hex(hexenc, *args[1:], **{k: v for k, v in kwargs.items() if k != 'data'})
        self.assertEqual(dec, self.data)

    # ── encrypt ──────────────────────────────────────────────────────────

    def test_encrypt_both_positional(self):
        self._try_encrypt(self.data, self.key)

    def test_encrypt_data_positional_key_keyword(self):
        self._try_encrypt(self.data, key=self.key)

    def test_encrypt_both_keyword(self):
        self._try_encrypt(data=self.data, key=self.key)

    def test_encrypt_both_keyword_swapped(self):
        self._try_encrypt(key=self.key, data=self.data)

    def test_encrypt_all_positional_with_padding(self):
        self._try_encrypt(self.data, self.key, True)

    def test_encrypt_all_positional_with_padding_and_rounds(self):
        self._try_encrypt(self.data, self.key, True, 32)

    def test_encrypt_padding_keyword(self):
        self._try_encrypt(self.data, self.key, padding=True)

    def test_encrypt_rounds_keyword(self):
        self._try_encrypt(self.data, self.key, rounds=32)

    def test_encrypt_both_optional_keyword(self):
        self._try_encrypt(self.data, self.key, padding=True, rounds=32)

    def test_encrypt_positional_padding_rounds(self):
        """Regression: positional padding/rounds must work."""
        enc_pos = xxteang.encrypt(self.data, self.key, True, 32)
        enc_kw  = xxteang.encrypt(self.data, self.key, padding=True, rounds=32)
        self.assertEqual(enc_pos, enc_kw)
        dec = xxteang.decrypt(enc_pos, self.key, True, 32)
        self.assertEqual(dec, self.data)
        # Verify round-trip: positional encrypt with helper (uses keyword)
        dec2 = xxteang.decrypt(enc_pos, self.key, rounds=32)
        self.assertEqual(dec2, self.data)

    def test_decrypt_positional_padding_rounds(self):
        """Regression: positional padding/rounds must work."""
        enc = xxteang.encrypt(self.data, self.key, True, 32)
        dec = xxteang.decrypt(enc, self.key, True, 32)
        self.assertEqual(dec, self.data)

    def test_positional_padding_only(self):
        """Regression: positional False at position 2."""
        enc_pos = xxteang.encrypt(self.data, self.key, False)
        enc_kw  = xxteang.encrypt(self.data, self.key, padding=False)
        self.assertEqual(enc_pos, enc_kw)
        dec = xxteang.decrypt(enc_pos, self.key, False)
        self.assertEqual(dec, self.data)

    def test_encrypt_nopadding_keyword(self):
        enc = xxteang.encrypt(self.data, self.key, padding=False)
        dec = xxteang.decrypt(enc, self.key, padding=False)
        self.assertEqual(dec, self.data)

    def test_encrypt_all_keyword(self):
        self._try_encrypt(data=self.data, key=self.key, padding=True, rounds=32)

    def test_encrypt_mixed_order(self):
        self._try_encrypt(key=self.key, padding=True, data=self.data)
        self._try_encrypt(rounds=32, key=self.key, data=self.data)

    # ── decrypt ──────────────────────────────────────────────────────────

    def test_decrypt_both_positional(self):
        self._try_decrypt(self.enc, self.key)

    def test_decrypt_data_positional_key_keyword(self):
        self._try_decrypt(self.enc, key=self.key)

    def test_decrypt_both_keyword(self):
        self._try_decrypt(data=self.enc, key=self.key)

    def test_decrypt_both_keyword_swapped(self):
        self._try_decrypt(key=self.key, data=self.enc)

    def test_decrypt_all_positional_with_padding(self):
        self._try_decrypt(self.enc, self.key, True)

    def test_decrypt_all_positional_with_padding_and_rounds(self):
        self._try_decrypt(self.enc, self.key, True, 32)

    def test_decrypt_padding_keyword(self):
        self._try_decrypt(self.enc, self.key, padding=True)

    def test_decrypt_rounds_keyword(self):
        self._try_decrypt(self.enc, self.key, rounds=32)

    def test_decrypt_both_optional_keyword(self):
        self._try_decrypt(self.enc, self.key, padding=True, rounds=32)

    def test_decrypt_nopadding_keyword(self):
        data_nopad = os.urandom(32)
        enc = xxteang.encrypt(data_nopad, self.key, padding=False)
        dec = xxteang.decrypt(enc, self.key, padding=False)
        self.assertEqual(dec, data_nopad)

    def test_decrypt_all_keyword(self):
        self._try_decrypt(data=self.enc, key=self.key, padding=True, rounds=32)

    def test_decrypt_mixed_order(self):
        self._try_decrypt(rounds=32, key=self.key, data=self.enc)

    # ── encrypt_hex ──────────────────────────────────────────────────────

    def test_encrypt_hex_both_positional(self):
        self._try_encrypt_hex(self.data, self.key)

    def test_encrypt_hex_key_keyword(self):
        self._try_encrypt_hex(self.data, key=self.key)

    def test_encrypt_hex_both_keyword(self):
        self._try_encrypt_hex(data=self.data, key=self.key)

    def test_encrypt_hex_both_keyword_swapped(self):
        self._try_encrypt_hex(key=self.key, data=self.data)

    def test_encrypt_hex_padding_keyword(self):
        self._try_encrypt_hex(self.data, self.key, padding=True)

    def test_encrypt_hex_rounds_keyword(self):
        self._try_encrypt_hex(self.data, self.key, rounds=32)

    def test_encrypt_hex_nopadding(self):
        enc = xxteang.encrypt_hex(self.data, self.key, padding=False)
        dec = xxteang.decrypt_hex(enc, self.key, padding=False)
        self.assertEqual(dec, self.data)

    def test_encrypt_hex_all_keyword(self):
        self._try_encrypt_hex(data=self.data, key=self.key, padding=True, rounds=32)

    def test_encrypt_hex_mixed_order(self):
        self._try_encrypt_hex(key=self.key, rounds=32, data=self.data)

    # ── decrypt_hex ──────────────────────────────────────────────────────

    def test_decrypt_hex_both_positional(self):
        self._try_decrypt_hex(self.hexenc, self.key)

    def test_decrypt_hex_key_keyword(self):
        self._try_decrypt_hex(self.hexenc, key=self.key)

    def test_decrypt_hex_both_keyword(self):
        self._try_decrypt_hex(data=self.hexenc, key=self.key)

    def test_decrypt_hex_both_keyword_swapped(self):
        self._try_decrypt_hex(key=self.key, data=self.hexenc)

    def test_decrypt_hex_padding_keyword(self):
        self._try_decrypt_hex(self.hexenc, self.key, padding=True)

    def test_decrypt_hex_rounds_keyword(self):
        self._try_decrypt_hex(self.hexenc, self.key, rounds=32)

    def test_decrypt_hex_nopadding(self):
        data_nopad = os.urandom(32)
        enc = xxteang.encrypt_hex(data_nopad, self.key, padding=False)
        dec = xxteang.decrypt_hex(enc, self.key, padding=False)
        self.assertEqual(dec, data_nopad)

    def test_decrypt_hex_all_keyword(self):
        self._try_decrypt_hex(data=self.hexenc, key=self.key, padding=True, rounds=32)

    def test_decrypt_hex_mixed_order(self):
        self._try_decrypt_hex(rounds=0, key=self.key, data=self.hexenc)

    # ── error cases ──────────────────────────────────────────────────────

    def test_missing_required_arg(self):
        with self.assertRaises(TypeError):
            xxteang.encrypt(self.data)
        with self.assertRaises(TypeError):
            xxteang.encrypt(key=self.key)
        with self.assertRaises(TypeError):
            xxteang.decrypt(self.enc)
        with self.assertRaises(TypeError):
            xxteang.encrypt_hex(self.data)
        with self.assertRaises(TypeError):
            xxteang.decrypt_hex(self.hexenc)

    def test_unknown_keyword(self):
        with self.assertRaises(TypeError):
            xxteang.encrypt(self.data, self.key, bogus=1)
        with self.assertRaises(TypeError):
            xxteang.decrypt(self.enc, self.key, bogus=1)
        with self.assertRaises(TypeError):
            xxteang.encrypt_hex(self.data, self.key, bogus=1)
        with self.assertRaises(TypeError):
            xxteang.decrypt_hex(self.hexenc, self.key, bogus=1)

    def test_duplicate_argument(self):
        with self.assertRaises(TypeError):
            xxteang.encrypt(self.data, self.key, data=self.data)
        with self.assertRaises(TypeError):
            xxteang.decrypt(self.enc, self.key, data=self.enc)

    def test_invalid_rounds_type(self):
        with self.assertRaises(TypeError):
            xxteang.encrypt(self.data, self.key, rounds='not-an-int')
        with self.assertRaises(TypeError):
            xxteang.decrypt(self.enc, self.key, rounds=1.5)

    def test_too_many_positional_args(self):
        with self.assertRaises(TypeError):
            xxteang.encrypt(self.data, self.key, True, 32, 'extra')
        with self.assertRaises(TypeError):
            xxteang.decrypt(self.enc, self.key, True, 32, 'extra')
        with self.assertRaises(TypeError):
            xxteang.encrypt_hex(self.data, self.key, True, 32, 'extra')
        with self.assertRaises(TypeError):
            xxteang.decrypt_hex(self.hexenc, self.key, True, 32, 'extra')

    def test_rounds_overflow(self):
        # overflow — keyword
        with self.assertRaises(OverflowError):
            xxteang.encrypt(self.data, self.key, rounds=2**32)
        with self.assertRaises(OverflowError):
            xxteang.decrypt(self.enc, self.key, rounds=2**32)
        with self.assertRaises(OverflowError):
            xxteang.encrypt_hex(self.data, self.key, rounds=2**32)
        with self.assertRaises(OverflowError):
            xxteang.decrypt_hex(self.hexenc, self.key, rounds=2**32)
        # overflow — positional
        with self.assertRaises(OverflowError):
            xxteang.encrypt(self.data, self.key, True, 2**32)
        with self.assertRaises(OverflowError):
            xxteang.decrypt(self.enc, self.key, True, 2**32)


class TestXXTEAType(unittest.TestCase):
    """Tests for the XXTEA type (cipher object)."""

    data = b'How do you do?'
    key = b'Fine. And you?  '
    enc = b'x\xf4e\xeb\x1bI\x85\x88}\x11\x84.\xde\x856!'

    @classmethod
    def setUpClass(cls):
        cls.cipher = xxteang.XXTEA(cls.key)

    # ── basic round-trip ────────────────────────────────────────────────

    def test_encrypt(self):
        enc = self.cipher.encrypt(self.data)
        self.assertEqual(enc, self.enc)

    def test_decrypt(self):
        data = self.cipher.decrypt(self.enc)
        self.assertEqual(data, self.data)

    def test_roundtrip(self):
        enc = self.cipher.encrypt(self.data)
        dec = self.cipher.decrypt(enc)
        self.assertEqual(dec, self.data)

    # ── random data ─────────────────────────────────────────────────────

    def test_urandom(self):
        for i in range(2048):
            key = os.urandom(16)
            data = os.urandom(i)
            cipher = xxteang.XXTEA(key)

            enc = cipher.encrypt(data)
            dec = cipher.decrypt(enc)
            self.assertEqual(data, dec)

    def test_zero_bytes(self):
        for i in range(2048):
            data = b'\0' * i

            key = os.urandom(16)
            cipher = xxteang.XXTEA(key)
            enc = cipher.encrypt(data)
            dec = cipher.decrypt(enc)
            self.assertEqual(data, dec)

            cipher2 = xxteang.XXTEA(b'\0' * 16)
            enc = cipher2.encrypt(data)
            dec = cipher2.decrypt(enc)
            self.assertEqual(data, dec)

    # ── no-padding ──────────────────────────────────────────────────────

    def test_encrypt_nopadding(self):
        key = os.urandom(16)
        cipher = xxteang.XXTEA(key, padding=False)
        for i in (8, 12, 16, 20):
            data = os.urandom(i)
            enc = cipher.encrypt(data)
            dec = cipher.decrypt(enc)
            self.assertEqual(data, dec)

    def test_encrypt_nopadding_zero(self):
        key = os.urandom(16)
        cipher = xxteang.XXTEA(key, padding=False)
        for i in (8, 12, 16, 20):
            data = b'\0' * i
            enc = cipher.encrypt(data)
            dec = cipher.decrypt(enc)
            self.assertEqual(data, dec)

    # ── rounds ──────────────────────────────────────────────────────────

    def test_rounds(self):
        key = os.urandom(16)
        data = os.urandom(32)

        for r in (0, 1, 8, 32, 64, 128, 256):
            cipher = xxteang.XXTEA(key, rounds=r)
            enc = cipher.encrypt(data)
            dec = cipher.decrypt(enc)
            self.assertEqual(data, dec)

    def test_different_rounds_produce_different_output(self):
        key = os.urandom(16)
        data = os.urandom(32)
        c0 = xxteang.XXTEA(key, rounds=0)
        c32 = xxteang.XXTEA(key, rounds=32)
        self.assertNotEqual(c0.encrypt(data), c32.encrypt(data))

    # ── matches module-level functions ──────────────────────────────────

    def test_matches_module_encrypt(self):
        key = os.urandom(16)
        data = os.urandom(32)
        cipher = xxteang.XXTEA(key)
        self.assertEqual(cipher.encrypt(data), xxteang.encrypt(data, key))

    def test_matches_module_decrypt(self):
        key = os.urandom(16)
        data = os.urandom(32)
        enc = xxteang.encrypt(data, key)
        cipher = xxteang.XXTEA(key)
        self.assertEqual(cipher.decrypt(enc), xxteang.decrypt(enc, key))

    def test_matches_module_with_rounds(self):
        key = os.urandom(16)
        data = os.urandom(32)
        cipher = xxteang.XXTEA(key, rounds=42)
        enc_c = cipher.encrypt(data)
        enc_m = xxteang.encrypt(data, key, rounds=42)
        self.assertEqual(enc_c, enc_m)
        self.assertEqual(cipher.decrypt(enc_m), xxteang.decrypt(enc_c, key, rounds=42))

    def test_matches_module_nopadding(self):
        key = os.urandom(16)
        data = os.urandom(32)
        cipher = xxteang.XXTEA(key, padding=False)
        enc_c = cipher.encrypt(data)
        enc_m = xxteang.encrypt(data, key, padding=False)
        self.assertEqual(enc_c, enc_m)

    # ── error cases ─────────────────────────────────────────────────────

    def test_short_key(self):
        with self.assertRaises(ValueError):
            xxteang.XXTEA(b'short')
        with self.assertRaises(ValueError):
            xxteang.XXTEA(b'this key is way too long!!!')

    def test_rounds_overflow(self):
        with self.assertRaises(OverflowError):
            xxteang.XXTEA(self.key, rounds=2**32)

    def test_missing_required_arg(self):
        with self.assertRaises(TypeError):
            xxteang.XXTEA()

    def test_invalid_rounds_type(self):
        with self.assertRaises(TypeError):
            xxteang.XXTEA(self.key, rounds='not-an-int')

    # ── hex methods ─────────────────────────────────────────────────────

    def test_encrypt_hex(self):
        key = os.urandom(16)
        data = os.urandom(32)
        cipher = xxteang.XXTEA(key)
        hexenc = cipher.encrypt_hex(data)
        dec = cipher.decrypt_hex(hexenc)
        self.assertEqual(dec, data)

    def test_encrypt_hex_matches(self):
        key = os.urandom(16)
        data = os.urandom(32)
        cipher = xxteang.XXTEA(key)
        self.assertEqual(cipher.encrypt_hex(data),
                         xxteang.encrypt_hex(data, key))

    def test_decrypt_hex_matches(self):
        key = os.urandom(16)
        data = os.urandom(32)
        hexenc = xxteang.encrypt_hex(data, key)
        cipher = xxteang.XXTEA(key)
        self.assertEqual(cipher.decrypt_hex(hexenc),
                         xxteang.decrypt_hex(hexenc, key))

    def test_decrypt_hex_invalid(self):
        """Non-hex digits and odd-length hex strings are rejected."""
        with self.assertRaises(binascii.Error):
            xxteang.decrypt_hex(b'zz', os.urandom(16))
        with self.assertRaises(binascii.Error):
            xxteang.decrypt_hex(b'abc', os.urandom(16))
        with self.assertRaises(binascii.Error):
            self.cipher.decrypt_hex(b'zz')

    # ── padding at construction ──────────────────────────────────────────

    def test_padding_construction(self):
        key = os.urandom(16)
        for padding in (True, False):
            cipher = xxteang.XXTEA(key, padding=padding)
            self.assertEqual(cipher.decrypt(cipher.encrypt(b'12345678')), b'12345678')


class TestBytesLikeInputs(unittest.TestCase):
    """The buffer protocol (PyBUF_SIMPLE) accepts bytes-like objects
    for both data and key."""

    def test_module_functions(self):
        key = os.urandom(16)
        data = os.urandom(32)
        for data_buf in (bytearray(data), memoryview(data)):
            for key_buf in (bytearray(key), memoryview(key)):
                enc = xxteang.encrypt(data_buf, key_buf)
                self.assertEqual(xxteang.decrypt(enc, key), data)
                hexenc = xxteang.encrypt_hex(data_buf, key_buf)
                self.assertEqual(xxteang.decrypt_hex(hexenc, key), data)

    def test_type_methods(self):
        key = os.urandom(16)
        data = os.urandom(32)
        cipher = xxteang.XXTEA(bytearray(key))
        for data_buf in (bytearray(data), memoryview(data)):
            enc = cipher.encrypt(data_buf)
            self.assertEqual(cipher.decrypt(enc), data)
            hexenc = cipher.encrypt_hex(data_buf)
            self.assertEqual(cipher.decrypt_hex(hexenc), data)


if __name__ == '__main__':
    unittest.main()
