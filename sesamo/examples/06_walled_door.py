"""A door that cannot open: the two conditions contradict each other.
There is no bug here - and Z3 PROVES it, instead of guessing forever."""


def target(n):
    if n > 10:
        if n < 5:
            return 1 / 0
    return n
