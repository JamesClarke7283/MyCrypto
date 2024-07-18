from src.rand.base import RandomInteger
from src.rand.simple import LinearCongruentialGenerator
import unittest


class TestLCG(unittest.TestCase):
    def test_random_int_sequence(self):
        ri = RandomInteger(minimum=1, maximum=100, func=LinearCongruentialGenerator, seed=10)
        # Ensure that a sequence of 10 numbers are all within the expected range
        for _ in range(10):
            num = ri.next()
            self.assertGreaterEqual(num, 1)
            self.assertLessEqual(num, 100)

    def test_random_int_deterministic(self):
        # Ensure that for a fixed seed, the sequence of numbers is deterministic (i.e., the same every time)
        ri1 = RandomInteger(minimum=1, maximum=100, func=LinearCongruentialGenerator, seed=10)
        ri2 = RandomInteger(minimum=1, maximum=100, func=LinearCongruentialGenerator, seed=10)

        for _ in range(10):
            self.assertEqual(ri1.next(), ri2.next())


if __name__ == "__main__":
    unittest.main()
