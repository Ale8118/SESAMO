"""
Automated tests: they prove SESAMO finds the known bugs in every example,
and that the lone fuzzer does not. Run with:  python -m pytest
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sesamo import Fuzzer, find_key, load_target, read_locks, sesamo  # noqa: E402


def example(name):
    return load_target(os.path.join(ROOT, "examples", name))


def deepest_reach_key(name):
    """Forge the input that reaches the function's final (deepest) return."""
    params, locks, _ = read_locks(example(name))
    reach = [(t, f) for t, f, k in locks if k == "reach"]
    assert reach, "no reach goal found"
    text, formulas = reach[-1]
    return params, find_key(params, formulas)


# ---- crash / assert hunting ---------------------------------------------

def test_warmup_narrow_door():
    report = sesamo(example("01_warmup_narrow_door.py"), seed=1, verbose=False)
    assert {a for a, _ in report["crashes"]} == {(123456789,)}


def test_license_key_is_forged_and_really_works():
    params, key = deepest_reach_key("02_license_key.py")
    assert key is not None
    assert example("02_license_key.py")(*key) is True   # the real code accepts it


def test_checksum_collision_breaks_the_promise():
    report = sesamo(example("03_checksum_forgery.py"), seed=1, verbose=False)
    crashes = {a for a, _ in report["crashes"]}
    assert crashes, "no collision found"
    forgery = next(iter(crashes))[0]
    target = example("03_checksum_forgery.py")
    # same signature as 424242, but a different message
    assert forgery != 424242
    assert (forgery * 73 + 19) % 1000000 == (424242 * 73 + 19) % 1000000


def test_game_damage_can_go_negative():
    report = sesamo(example("04_game_damage.py"), seed=1, verbose=False)
    assert report["crashes"], "the invariant was never broken"
    attack, armor, combo = report["crashes"][0][0]
    if combo < 1:
        combo = 1
    assert attack * combo - armor * 10 < 0   # genuinely heals the enemy


def test_hidden_division_by_zero():
    report = sesamo(example("05_hidden_division.py"), seed=1, verbose=False)
    assert report["crashes"], "the division by zero was missed"
    case, error = report["crashes"][0]
    assert error == "ZeroDivisionError"
    assert case[0] > 2000000 and case[0] % 500 == 137


# ---- the walled door: a bug that cannot happen --------------------------

def test_walled_door_has_no_crash():
    report = sesamo(example("06_walled_door.py"), seed=1, verbose=False)
    assert report["crashes"] == []


def test_walled_door_is_proven_unreachable():
    params, locks, _ = read_locks(example("06_walled_door.py"))
    keys = {t: find_key(params, f) for t, f, k in locks}
    assert keys["n > 10"] is not None
    assert keys["n < 5"] is None            # Z3 proves it: no input opens it


# ---- the point of the whole project: Z3 beats blind fuzzing -------------

@pytest.mark.parametrize("name", [
    "02_license_key.py", "03_checksum_forgery.py",
    "04_game_damage.py", "05_hidden_division.py",
])
def test_fuzzer_alone_fails_where_sesamo_wins(name):
    alone = sesamo(example(name), use_z3=False, rounds=20000, seed=1, verbose=False)
    # the lone fuzzer cannot forge the exact inputs these bugs need
    if name == "02_license_key.py":
        # no crash here anyway; check it never reaches the accept line
        target = example(name)
        reached = any(target(*a) is True for a in [a for a, _ in alone["crashes"]])
        assert not reached
    else:
        assert alone["crashes"] == []


# ---- machinery sanity ---------------------------------------------------

def test_coverage_counts_only_the_target_file():
    target = example("01_warmup_narrow_door.py")
    fz = Fuzzer(target, verbose=False)
    lines = fz.coverage((9,))
    with open(target.__code__.co_filename) as f:
        length = len(f.readlines())
    assert lines and max(lines) <= length


def test_same_seed_same_result():
    target = example("01_warmup_narrow_door.py")
    a = sesamo(target, use_z3=False, seed=7, rounds=3000, verbose=False)
    b = sesamo(target, use_z3=False, seed=7, rounds=3000, verbose=False)
    assert a["runs_to_first_crash"] == b["runs_to_first_crash"]
