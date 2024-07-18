
class RandomInteger:
    def __init__(self, minimum, maximum, func, seed=0):
        self.minimum = minimum
        self.maximum = maximum
        self.func = func
        self.seed = seed

    def next(self):
        self.seed = self.minimum + self.func(seed=self.seed).next() % (self.maximum - self.minimum + 1)
        return self.seed
