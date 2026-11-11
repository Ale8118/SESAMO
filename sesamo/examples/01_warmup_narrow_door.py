"""Warm-up. A single exact value opens the crash. One number in hundreds of
millions - random fuzzing never guesses it, Z3 reads it straight off the door."""


def target(n):
    if n < 0:
        return "error"
    if n == 123456789:
        return 1 / 0
    return n ** 0.5
