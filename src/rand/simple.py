class LinearCongruentialGenerator:
    def __init__(self, seed=0, multiplier=25214903917, increment=11, modulus=2**48):
        self.current_value = seed
        self.multiplier = multiplier
        self.increment = increment
        self.modulus = modulus

    def next(self):
        self.current_value = (self.multiplier * self.current_value + self.increment) % self.modulus
        return self.current_value
