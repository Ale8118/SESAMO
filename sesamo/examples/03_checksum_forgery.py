"""
CRYPTOGRAPHY - a home-made checksum, and why you should never roll your own.

`sign(x)` stamps a number with a short 'signature'. The promise an assert makes:
two different inputs should never share a signature (no collisions). SESAMO
finds a second number with the SAME signature - it forges the stamp - and the
assert fires. (A real hash like SHA-256 would survive this; see the README's
limits section.)
"""


def target(message):
    signature = (message * 73 + 19) % 1000000
    # the system elsewhere trusts this signature to identify the message.
    # promise: the special document 424242 is the ONLY one with its signature.
    if signature == (424242 * 73 + 19) % 1000000:
        assert message == 424242   # SESAMO will find a forgery that breaks this
    return signature
