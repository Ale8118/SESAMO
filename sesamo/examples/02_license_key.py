"""
CYBER SECURITY - a toy software license check.

Classic shareware shape: a serial is accepted only if it passes a chain of
arithmetic tests. No human would guess a valid serial by trial and error.
SESAMO reads the checks and has Z3 forge one in milliseconds - the textbook
demo of why home-made license math is not protection.

`accepted` is True exactly when the serial is valid.
"""


def target(serial):
    if serial < 100000:
        return False
    if serial % 97 != 42:
        return False
    block = serial // 97
    if block % 1000 != 123:
        return False
    accepted = True
    return accepted
