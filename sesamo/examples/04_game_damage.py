"""
VIDEO GAME - a frame-perfect exploit, the kind speedrunners hunt for.

Damage is clamped so a hit can never heal the target: the designer writes
that belief as an assert. But on one exact frame (216000 = one hour at 60fps)
a mistimed calculation flips the sign and the hit HEALS the enemy. No player
reaches that precise frame by mashing buttons, and a blind fuzzer never lands
on it either. SESAMO reads the condition and Z3 names the frame at once.
"""


def target(attack, armor, frame):
    if attack < 0:
        attack = 0
    if attack > 100:
        attack = 100
    base = attack - armor
    if base < 0:
        base = 0
    damage = base
    if frame == 216000:
        damage = -base * 50      # frame-perfect sign flip: the hit heals
    assert damage >= 0           # designer's belief: a hit never heals
    return damage
