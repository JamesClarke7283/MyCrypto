from .serpent import Serpent
import logging

logger = logging.getLogger(__name__)

def encrypt_ecb(key: bytes, plaintext: bytes) -> bytes:
    serpent = Serpent(key)
    ciphertext = b''
    for i in range(0, len(plaintext), Serpent.BLOCK_SIZE):
        block = plaintext[i:i+Serpent.BLOCK_SIZE]
        if len(block) < Serpent.BLOCK_SIZE:
            block = block.ljust(Serpent.BLOCK_SIZE, b'\x00')  # PKCS7 padding
        logger.debug(f"Encrypting block: {block.hex()}")
        ciphertext += serpent.encrypt(block)
    logger.info(f"Encrypted {len(plaintext)} bytes of data")
    return ciphertext

def decrypt_ecb(key: bytes, ciphertext: bytes) -> bytes:
    serpent = Serpent(key)
    plaintext = b''
    for i in range(0, len(ciphertext), Serpent.BLOCK_SIZE):
        block = ciphertext[i:i+Serpent.BLOCK_SIZE]
        logger.debug(f"Decrypting block: {block.hex()}")
        plaintext += serpent.decrypt(block)
    # Remove padding
    plaintext = plaintext.rstrip(b'\x00')
    logger.info(f"Decrypted {len(ciphertext)} bytes of data")
    return plaintext

if __name__ == "__main__":
    import unittest
    from tests.cipher.block.serpent.test_ecb import TestSerpentECB
    unittest.main()
