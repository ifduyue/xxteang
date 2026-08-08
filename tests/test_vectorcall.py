import unittest
import xxteang


class TestVectorcall(unittest.TestCase):
    def test_object_methods_vectorcall(self):
        c = xxteang.XXTEA(b'0123456789abcdef')
        self.assertEqual(c.encrypt(b'a'), xxteang.encrypt(b'a', b'0123456789abcdef'))
        self.assertEqual(c.decrypt(c.encrypt(b'a')), b'a')
        self.assertEqual(c.encrypt_hex(b'a'), xxteang.encrypt_hex(b'a', b'0123456789abcdef'))
        self.assertEqual(c.decrypt_hex(c.encrypt_hex(b'a')), b'a')

    def test_init_keywords(self):
        c = xxteang.XXTEA(key=b'0123456789abcdef', padding=False, rounds=16)
        self.assertEqual(c.encrypt(b'12345678'), xxteang.encrypt(b'12345678', b'0123456789abcdef', False, 16))

    def test_init_positional(self):
        c = xxteang.XXTEA(b'0123456789abcdef', False, 16)
        self.assertEqual(c.encrypt(b'12345678'), xxteang.encrypt(b'12345678', b'0123456789abcdef', False, 16))

    def test_init_mixed(self):
        c = xxteang.XXTEA(b'0123456789abcdef', rounds=16)
        self.assertEqual(c.encrypt(b'12345678'), xxteang.encrypt(b'12345678', b'0123456789abcdef', rounds=16))

    # ── error paths (vectorcall constructor) ──────────────────────

    def test_missing_key(self):
        with self.assertRaises(TypeError):
            xxteang.XXTEA()

    def test_unknown_keyword(self):
        with self.assertRaises(TypeError):
            xxteang.XXTEA(b'0123456789abcdef', bogus=1)

    def test_duplicate_key(self):
        with self.assertRaises(TypeError):
            xxteang.XXTEA(b'0123456789abcdef', key=b'0123456789abcdef')

    def test_short_key(self):
        with self.assertRaises(ValueError):
            xxteang.XXTEA(b'short')

    def test_invalid_rounds_type(self):
        with self.assertRaises(TypeError):
            xxteang.XXTEA(b'0123456789abcdef', rounds='not-an-int')

    def test_rounds_overflow(self):
        with self.assertRaises(OverflowError):
            xxteang.XXTEA(b'0123456789abcdef', rounds=2**32)

    def test_too_many_positional(self):
        with self.assertRaises(TypeError):
            xxteang.XXTEA(b'0123456789abcdef', True, 32, 'extra')

    def test_duplicate_padding(self):
        with self.assertRaises(TypeError):
            xxteang.XXTEA(b'0123456789abcdef', True, padding=False)

    def test_duplicate_rounds(self):
        with self.assertRaises(TypeError):
            xxteang.XXTEA(b'0123456789abcdef', True, 32, rounds=42)

    def test_padding_keyword_only(self):
        c = xxteang.XXTEA(b'0123456789abcdef', padding=True)
        self.assertEqual(c.encrypt(b'12345678'), xxteang.encrypt(b'12345678', b'0123456789abcdef'))

    # ── legacy tp_init path (direct __init__ calls) ──────────────────

    def test_legacy_init_positional(self):
        c = xxteang.XXTEA.__new__(xxteang.XXTEA)
        xxteang.XXTEA.__init__(c, b'0123456789abcdef')
        self.assertEqual(c.encrypt(b'a'), xxteang.encrypt(b'a', b'0123456789abcdef'))

    def test_legacy_init_keywords(self):
        c = xxteang.XXTEA.__new__(xxteang.XXTEA)
        xxteang.XXTEA.__init__(c, key=b'0123456789abcdef', padding=False, rounds=16)
        self.assertEqual(c.encrypt(b'12345678'),
                         xxteang.encrypt(b'12345678', b'0123456789abcdef', False, 16))

    def test_legacy_init_errors(self):
        c = xxteang.XXTEA.__new__(xxteang.XXTEA)
        with self.assertRaises(TypeError):  # too many arguments
            xxteang.XXTEA.__init__(c, b'0123456789abcdef', True, 32, 'extra')
        with self.assertRaises(TypeError):  # duplicate key
            xxteang.XXTEA.__init__(c, b'0123456789abcdef', key=b'0123456789abcdef')
        with self.assertRaises(TypeError):  # missing key
            xxteang.XXTEA.__init__(c)
        with self.assertRaises(ValueError):  # short key
            xxteang.XXTEA.__init__(c, b'short')


if __name__ == '__main__':
    unittest.main()
