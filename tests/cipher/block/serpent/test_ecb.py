import unittest
from src.cipher.block.serpent.ecb import encrypt_ecb, decrypt_ecb

class TestSerpentECB(unittest.TestCase):
    def setUp(self):
        self.key = b'0123456789abcdef0123456789abcdef'  # 256-bit key

    def test_encrypt_decrypt_single_block(self):
        plaintext = b'A' * 16  # One block
        ciphertext = encrypt_ecb(self.key, plaintext)
        decrypted = decrypt_ecb(self.key, ciphertext)
        self.assertEqual(plaintext, decrypted)

    def test_encrypt_decrypt_multiple_blocks(self):
        plaintext = b'This is a test message for Serpent ECB encryption.'
        ciphertext = encrypt_ecb(self.key, plaintext)
        decrypted = decrypt_ecb(self.key, ciphertext)
        self.assertEqual(plaintext, decrypted)

    def test_encrypt_decrypt_partial_block(self):
        plaintext = b'Partial block.'  # 14 bytes
        ciphertext = encrypt_ecb(self.key, plaintext)
        decrypted = decrypt_ecb(self.key, ciphertext)
        self.assertEqual(plaintext, decrypted)

    def test_different_keys_produce_different_ciphertexts(self):
        plaintext = b'Same plaintext.'
        key1 = self.key
        key2 = b'fedcba9876543210fedcba9876543210'  # Different 256-bit key
        ciphertext1 = encrypt_ecb(key1, plaintext)
        ciphertext2 = encrypt_ecb(key2, plaintext)
        self.assertNotEqual(ciphertext1, ciphertext2)

    def test_ciphertext_length_multiple_of_block_size(self):
        plaintext_lengths = [15, 16, 17, 31, 32, 33]
        for length in plaintext_lengths:
            plaintext = b'A' * length
            ciphertext = encrypt_ecb(self.key, plaintext)
            self.assertEqual(len(ciphertext) % 16, 0)  # 16 is the block size

    def test_decrypt_wrong_length_ciphertext(self):
        ciphertext = b'A' * 15  # Not a multiple of block size
        with self.assertRaises(ValueError):
            decrypt_ecb(self.key, ciphertext)

if __name__ == "__main__":
    unittest.main()
