import struct
import logging
from typing import List

# Set up logging
TRACE = 5  # Custom TRACE level
logging.addLevelName(TRACE, "TRACE")

def trace(self, message, *args, **kws):
    if self.isEnabledFor(TRACE):
        self._log(TRACE, message, args, **kws)

logging.Logger.trace = trace

# Configure logging to file
logging.basicConfig(
    level=TRACE,
    format='%(asctime)s %(levelname)s:%(message)s',
    handlers=[logging.FileHandler('serpent.log', 'w'), logging.StreamHandler()]
)

logger = logging.getLogger(__name__)

class Serpent:
    BLOCK_SIZE = 16  # 128 bits
    KEY_SIZE = 32    # 256 bits
    ROUNDS = 32

    def __init__(self, key: bytes):
        if len(key) not in (16, 24, 32):
            raise ValueError("Key must be 128, 192, or 256 bits long")
        self.key = self._pad_key(key)
        logger.debug(f"Padded key: {self.key.hex()}")
        self.round_keys = self._generate_round_keys()
        logger.debug(f"Generated {len(self.round_keys)} round keys")

    @staticmethod
    def _pad_key(key: bytes) -> bytes:
        if len(key) == 32:
            return key
        return key.ljust(32, b'\x00')

    def _generate_round_keys(self) -> List[List[int]]:
        logger.debug("Generating round keys")
        w = list(struct.unpack('>8I', self.key)) + [0] * 132
        phi = 0x9e3779b9
        for i in range(8, 140):
            w[i] = (w[i-8] ^ w[i-5] ^ w[i-3] ^ w[i-1] ^ phi ^ (i-8)) & 0xFFFFFFFF
            w[i] = ((w[i] << 11) | (w[i] >> 21)) & 0xFFFFFFFF
            logger.trace(f"w[{i}] = {w[i]:08x}")
        
        keys = []
        for i in range(33):
            s_box = self.S_BOXES[i % 8]
            keys.append(self._apply_sbox(w[4*i:4*i+4], s_box))
            logger.trace(f"Round key {i}: {keys[-1]}")
        
        return keys

    @staticmethod
    def _apply_sbox(words: List[int], s_box: List[int]) -> List[int]:
        result = []
        for word in words:
            output = 0
            for i in range(32, 0, -4):
                output |= s_box[(word >> (i-4)) & 0xF] << (i-4)
                logger.trace(f"Word {word:08x}: S-box bit {i} -> {output:08x}")
            result.append(output & 0xFFFFFFFF)
        return result

    def encrypt(self, plaintext: bytes) -> bytes:
        if len(plaintext) != self.BLOCK_SIZE:
            raise ValueError(f"Plaintext must be exactly {self.BLOCK_SIZE} bytes long")
        
        logger.debug(f"Encrypting block: {plaintext.hex()}")
        state = self._initial_permutation(plaintext)
        logger.trace(f"After initial permutation: {state.hex()}")
        
        for i in range(self.ROUNDS):
            state = self._round(state, i)
            logger.trace(f"After round {i}: {state.hex()}")
        
        ciphertext = self._final_permutation(state)
        logger.debug(f"Ciphertext: {ciphertext.hex()}")
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) != self.BLOCK_SIZE:
            raise ValueError(f"Ciphertext must be exactly {self.BLOCK_SIZE} bytes long")
        
        logger.debug(f"Decrypting block: {ciphertext.hex()}")
        state = self._initial_permutation(ciphertext)
        logger.trace(f"After initial permutation: {state.hex()}")
        
        for i in range(self.ROUNDS - 1, -1, -1):
            state = self._inverse_round(state, i)
            logger.trace(f"After inverse round {i}: {state.hex()}")
        
        plaintext = self._final_permutation(state)
        logger.debug(f"Decrypted plaintext: {plaintext.hex()}")
        return plaintext

    def _round(self, state: bytes, round_num: int) -> bytes:
        logger.trace(f"Starting round {round_num} with state: {state.hex()}")
        state = bytes(a ^ b for a, b in zip(state, struct.pack('>4I', *self.round_keys[round_num])))
        state = self._sbox_substitution(state, round_num % 8)
        if round_num < self.ROUNDS - 1:
            state = self._linear_transformation(state)
        else:
            state = bytes(a ^ b for a, b in zip(state, struct.pack('>4I', *self.round_keys[round_num + 1])))
        logger.trace(f"Ending round {round_num} with state: {state.hex()}")
        return state

    def _inverse_round(self, state: bytes, round_num: int) -> bytes:
        logger.trace(f"Starting inverse round {round_num} with state: {state.hex()}")
        if round_num < self.ROUNDS - 1:
            state = self._inverse_linear_transformation(state)
        else:
            state = bytes(a ^ b for a, b in zip(state, struct.pack('>4I', *self.round_keys[round_num + 1])))
        state = self._inverse_sbox_substitution(state, round_num % 8)
        state = bytes(a ^ b for a, b in zip(state, struct.pack('>4I', *self.round_keys[round_num])))
        logger.trace(f"Ending inverse round {round_num} with state: {state.hex()}")
        return state

    @staticmethod
    def _initial_permutation(block: bytes) -> bytes:
        result = 0
        for i in range(128):
            bit = (block[i // 8] >> (i % 8)) & 1
            result |= bit << ((i // 8) * 8 + (i % 8))
            logger.trace(f"Initial permutation: bit {i} -> {bit}")
        return result.to_bytes(16, byteorder='big')

    @staticmethod
    def _final_permutation(block: bytes) -> bytes:
        result = 0
        for i in range(128):
            bit = (block[i // 8] >> (i % 8)) & 1
            result |= bit << ((i // 8) * 8 + (i % 8))
            logger.trace(f"Final permutation: bit {i} -> {bit}")
        return result.to_bytes(16, byteorder='big')

    def _sbox_substitution(self, state: bytes, box_num: int) -> bytes:
        s_box = self.S_BOXES[box_num]
        logger.trace(f"S-box substitution with box {box_num}")
        return bytes(s_box[b >> 4] << 4 | s_box[b & 0xF] for b in state)

    def _inverse_sbox_substitution(self, state: bytes, box_num: int) -> bytes:
        inv_s_box = self.INV_S_BOXES[box_num]
        logger.trace(f"Inverse S-box substitution with box {box_num}")
        return bytes(inv_s_box[b >> 4] << 4 | inv_s_box[b & 0xF] for b in state)

    @staticmethod
    def _linear_transformation(state: bytes) -> bytes:
        x = list(struct.unpack('>4I', state))
        y = [0, 0, 0, 0]
        y[0] = ((x[0] << 13) | (x[0] >> 19)) & 0xFFFFFFFF
        y[2] = ((x[2] << 13) | (x[2] >> 19)) & 0xFFFFFFFF
        y[1] = ((x[1] << 3) | (x[1] >> 29)) & 0xFFFFFFFF
        y[3] = ((x[3] << 3) | (x[3] >> 29)) & 0xFFFFFFFF
        y[0] ^= x[3]
        y[1] ^= x[0]
        y[2] ^= x[1]
        y[3] ^= x[2]
        y[1] ^= y[0]
        y[3] ^= y[2]
        y[1] = ((y[1] << 1) | (y[1] >> 31)) & 0xFFFFFFFF
        y[3] = ((y[3] << 1) | (y[3] >> 31)) & 0xFFFFFFFF
        logger.trace(f"Linear transformation: x -> {x}, y -> {y}")
        return struct.pack('>4I', y[0], y[1], y[2], y[3])

    @staticmethod
    def _inverse_linear_transformation(state: bytes) -> bytes:
        y = list(struct.unpack('>4I', state))
        x = [0, 0, 0, 0]
        x[2] = ((y[2] << 19) | (y[2] >> 13)) & 0xFFFFFFFF
        x[0] = ((y[0] << 19) | (y[0] >> 13)) & 0xFFFFFFFF
        x[1] = ((y[1] >> 1) | (y[1] << 31)) & 0xFFFFFFFF
        x[3] = ((y[3] >> 1) | (y[3] << 31)) & 0xFFFFFFFF
        x[0] ^= y[3]
        x[1] ^= y[0]
        x[2] ^= y[1]
        x[3] ^= y[2]
        x[1] ^= x[0]
        x[3] ^= x[2]
        x[1] = ((x[1] >> 3) | (x[1] << 29)) & 0xFFFFFFFF
        x[3] = ((x[3] >> 3) | (x[3] << 29)) & 0xFFFFFFFF
        logger.trace(f"Inverse linear transformation: y -> {y}, x -> {x}")
        return struct.pack('>4I', x[0], x[1], x[2], x[3])

    # S-boxes and their inverses
    S_BOXES = [
        [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
        [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
        [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
        [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 5, 14],
        [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
        [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
        [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
        [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6]
    ]

    INV_S_BOXES = [
        [13, 3, 11, 0, 10, 6, 5, 12, 1, 14, 4, 7, 15, 9, 8, 2],
        [5, 8, 2, 14, 15, 6, 12, 3, 11, 4, 7, 9, 1, 13, 10, 0],
        [12, 9, 15, 4, 11, 14, 1, 2, 0, 3, 6, 13, 5, 8, 10, 7],
        [0, 9, 10, 7, 11, 14, 6, 13, 3, 5, 12, 2, 4, 8, 15, 1],
        [5, 0, 8, 3, 10, 9, 7, 14, 2, 12, 11, 6, 4, 15, 13, 1],
        [8, 15, 2, 9, 4, 1, 13, 14, 11, 6, 5, 3, 7, 12, 10, 0],
        [15, 10, 1, 13, 5, 3, 6, 0, 4, 9, 14, 7, 2, 12, 8, 11],
        [3, 0, 6, 13, 9, 14, 15, 8, 5, 12, 11, 7, 10, 1, 4, 2]
    ]

if __name__ == "__main__":
    import unittest
    from tests.cipher.block.serpent.test_serpent import TestSerpent
    unittest.main()
