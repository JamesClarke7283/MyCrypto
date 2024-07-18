import unittest
from src.cipher.block.serpent.serpent import Serpent

class TestSerpent(unittest.TestCase):
    def test_encrypt_decrypt(self):
        key = b'0123456789abcdef0123456789abcdef'
        plaintext = b'A' * 16
        serpent = Serpent(key)
        ciphertext = serpent.encrypt(plaintext)
        decrypted = serpent.decrypt(ciphertext)
        self.assertEqual(plaintext, decrypted)

    def test_key_lengths(self):
        valid_keys = [b'0' * 16, b'0' * 24, b'0' * 32]
        for key in valid_keys:
            serpent = Serpent(key)
            self.assertEqual(len(serpent.key), 32)

        with self.assertRaises(ValueError):
            Serpent(b'0' * 15)

    def test_block_size(self):
        key = b'0' * 32
        serpent = Serpent(key)
        with self.assertRaises(ValueError):
            serpent.encrypt(b'0' * 15)
        with self.assertRaises(ValueError):
            serpent.decrypt(b'0' * 17)

if __name__ == "__main__":
    unittest.main()
