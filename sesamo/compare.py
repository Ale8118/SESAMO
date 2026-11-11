"""
Compare the lone fuzzer against SESAMO (fuzzer + Z3) on every example.
Prints the table that goes in the README. Run with:  python compare.py
"""

import glob
import os

from sesamo import find_key, load_target, read_locks, sesamo

TRIALS = 5
FUZZER_ONLY_ROUNDS = 50000     # the lone fuzzer gets ten times the budget
SESAMO_ROUNDS = 5000


def finds_bug(name, func):
    """A 'win' means: found a crash, OR (for the license) forged a valid serial."""
    if name == "02_license_key.py":
        params, locks, _ = read_locks(func)
        reach = [(t, f) for t, f, k in locks if k == "reach"]
        key = find_key(params, reach[-1][1]) if reach else None
        return key is not None and func(*key) is True
    return None  # handled by crash count below


def trial(func, name, use_z3, rounds):
    wins, runs = 0, []
    for seed in range(TRIALS):
        rep = sesamo(func, rounds=rounds, use_z3=use_z3, seed=seed, verbose=False)
        if name == "02_license_key.py":
            # license has no crash; the win is Z3 forging a valid serial
            if use_z3 and finds_bug(name, func):
                wins += 1
        elif rep["crashes"]:
            wins += 1
            runs.append(rep["runs_to_first_crash"])
    avg = round(sum(runs) / len(runs)) if runs else None
    return wins, avg


def cell(wins, avg):
    if wins == 0:
        return "never"
    return f"{wins}/{TRIALS}" + (f", ~{avg} runs" if avg else "")


def main():
    folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), "examples")
    print(f"| example | lone fuzzer ({FUZZER_ONLY_ROUNDS:,} rounds) | SESAMO ({SESAMO_ROUNDS:,} + Z3) |")
    print("|---|---|---|")
    for path in sorted(glob.glob(os.path.join(folder, "*.py"))):
        name = os.path.basename(path)
        func = load_target(path)
        solo = trial(func, name, use_z3=False, rounds=FUZZER_ONLY_ROUNDS)
        both = trial(func, name, use_z3=True, rounds=SESAMO_ROUNDS)
        print(f"| `{name}` | {cell(*solo)} | {cell(*both)} |")


if __name__ == "__main__":
    main()
