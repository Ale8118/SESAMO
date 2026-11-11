"""
SESAMO - a coverage-guided fuzzer that asks Z3 for help when it gets
stuck in front of a locked door.

  The fuzzer runs through the maze of a program, keeping the inputs that
  reach new lines. When random mutation can no longer open a door - an
  exact condition like `serial == 4096` - it reads the door straight from
  the code, hands the lock to the Z3 solver, and gets back the key.

Command line:
    python sesamo.py examples/02_narrow_door.py

From code:
    from sesamo import sesamo
    report = sesamo(target_function)

A "target" is a plain Python function taking one or more integers.
A "crash" is any exception it raises - including an AssertionError, so
you can write `assert balance >= 0` and let SESAMO hunt for the input
that breaks the promise.
"""

import argparse
import ast
import importlib.util
import inspect
import itertools
import random
import sys
import textwrap
import time

from z3 import And, BoolVal, If, Int, Not, Or, Solver, sat


# =====================================================================
# PART 1 - THE FUZZER (runs through the maze)
# =====================================================================

class Fuzzer:
    """Throws inputs at the target and keeps the ones that reach new lines."""

    def __init__(self, function, seed=None, verbose=True):
        self.function = function
        self.target_file = function.__code__.co_filename
        self.arity = function.__code__.co_argcount    # how many arguments
        self.chance = random.Random(seed)             # the dice; a seed makes runs repeatable
        self.verbose = verbose

        self.seen_lines = set()        # every line ever reached
        self.corpus = []               # the interesting inputs, to mutate from
        self.crashes = []              # list of (input, error_name)
        self.runs = 0                  # how many times the target was executed
        self.runs_to_first_crash = None
        self.door_log = {}             # condition text -> (who opened it, when)

    def say(self, *things):
        if self.verbose:
            print(*things)

    def coverage(self, args):
        """Run the target once; return the set of lines it touched."""
        touched = set()

        def spy(frame, event, arg):
            if event == "line" and frame.f_code.co_filename == self.target_file:
                touched.add(frame.f_lineno)
            return spy

        self.runs += 1
        previous = sys.gettrace()
        sys.settrace(spy)
        try:
            self.function(*args)
        except Exception as error:
            sys.settrace(previous)
            self.record_crash(args, type(error).__name__)
        finally:
            sys.settrace(previous)
        return touched

    def record_crash(self, args, error_name):
        if self.runs_to_first_crash is None:
            self.runs_to_first_crash = self.runs
        if args not in [a for a, _ in self.crashes]:
            self.crashes.append((args, error_name))
            self.say(" ", fmt(args), "->", error_name, "!")

    def test(self, args):
        """Judge an input: keep it if it reached new lines. True if it was new."""
        lines = self.coverage(args)
        fresh = lines - self.seen_lines
        if fresh:
            self.seen_lines.update(fresh)
            self.corpus.append(args)
            return True
        return False

    def mutate(self, args):
        """Tweak one of the numbers: small step, big jump, or fresh restart."""
        args = list(args)
        i = self.chance.randrange(len(args))
        kind = self.chance.randint(1, 3)
        if kind == 1:
            args[i] += self.chance.randint(-2, 2)
        elif kind == 2:
            args[i] += self.chance.randint(-100, 100)
        else:
            args[i] = self.chance.randint(-1000, 1000)
        return tuple(args)

    def fuzz(self, rounds, stop_on_crash=True):
        for _ in range(rounds):
            if stop_on_crash and self.crashes:
                return
            self.test(self.mutate(self.chance.choice(self.corpus)))


def fmt(args):
    """Pretty-print an input tuple."""
    return "(" + ", ".join(str(a) for a in args) + ")"


# =====================================================================
# PART 2 - THE LOCK READER (reads the target's code)
# =====================================================================

def to_formula(node, state):
    """Turn a chunk of code into a Z3 formula, using the 'state' notebook."""
    if isinstance(node, ast.BoolOp):                       # "a and b", "a or b"
        parts = [to_formula(p, state) for p in node.values]
        return And(*parts) if isinstance(node.op, ast.And) else Or(*parts)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return Not(to_formula(node.operand, state))
    # Python's // is integer division; Z3 has no '//' operator, so translate
    # the arithmetic ourselves. For Z3 integers, '/' already floors.
    if isinstance(node, ast.BinOp):
        left, right = to_formula(node.left, state), to_formula(node.right, state)
        if isinstance(node.op, ast.FloorDiv):
            return left / right
        if isinstance(node.op, ast.Div):
            return left / right
        if isinstance(node.op, ast.Mod):
            return left % right
        if isinstance(node.op, ast.Mult):
            return left * right
        if isinstance(node.op, ast.Add):
            return left + right
        if isinstance(node.op, ast.Sub):
            return left - right
        if isinstance(node.op, ast.Pow):
            return left ** right
    value = eval(ast.unparse(node), {"__builtins__": {}}, dict(state))
    return BoolVal(value) if isinstance(value, bool) else value


def stored_names(node):
    """The variable names written inside a chunk of code."""
    return {p.id for p in ast.walk(node)
            if isinstance(p, ast.Name) and isinstance(p.ctx, ast.Store)}


def hunt_divisions(expr, state, path, locks):
    """Every division is a hidden door: it opens when the divisor is zero."""
    if expr is None:
        return
    for p in ast.walk(expr):
        if isinstance(p, ast.BinOp) and isinstance(p.op, (ast.Div, ast.FloorDiv, ast.Mod)):
            try:
                divisor = to_formula(p.right, state)
            except Exception:
                continue
            if isinstance(divisor, (int, float)):
                continue
            locks.append(("div-by-zero: " + ast.unparse(p.right) + " == 0",
                          path + [divisor == 0], "crash"))


def walk(body, state, path, locks, skipped, top=False):
    """
    Read statements top to bottom.
      state: the notebook, each variable -> its formula
      path:  the conditions already passed to get here
      top:   True only for the function's own body, so that "reach" goals
             are emitted only for returns that cleared every guard, not for
             the early `return error` guards nested inside ifs.
    Returns (updated path, True if this block always ends in return/raise).
    """
    for node in body:

        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name)):
            hunt_divisions(node.value, state, path, locks)
            name = node.targets[0].id
            try:
                state[name] = to_formula(node.value, state)
            except Exception:
                state.pop(name, None)
                skipped.append(ast.unparse(node))

        elif isinstance(node, ast.AugAssign) and isinstance(node.target, ast.Name):
            hunt_divisions(node.value, state, path, locks)
            name = node.target.id
            whole = ast.BinOp(left=ast.Name(id=name, ctx=ast.Load()), op=node.op, right=node.value)
            try:
                state[name] = to_formula(whole, state)
            except Exception:
                state.pop(name, None)
                skipped.append(ast.unparse(node))

        # assert cond  ->  the door is the VIOLATION: can cond be false here?
        elif isinstance(node, ast.Assert):
            hunt_divisions(node.test, state, path, locks)
            text = "assert fails: " + ast.unparse(node.test)
            try:
                locks.append((text, path + [Not(to_formula(node.test, state))], "assert"))
            except Exception:
                skipped.append("assert " + ast.unparse(node.test))

        elif isinstance(node, ast.If):
            hunt_divisions(node.test, state, path, locks)
            text = ast.unparse(node.test)
            try:
                formula = to_formula(node.test, state)
            except Exception:
                formula = None
                skipped.append("if " + text)

            if formula is None:
                walk(node.body, dict(state), path, locks, skipped)
                walk(node.orelse, dict(state), path, locks, skipped)
                for name in stored_names(node):
                    state.pop(name, None)
                continue

            locks.append((text, path + [formula], "branch"))
            state_yes, state_no = dict(state), dict(state)
            _, ends_yes = walk(node.body, state_yes, path + [formula], locks, skipped)
            _, ends_no = walk(node.orelse, state_no, path + [Not(formula)], locks, skipped)

            if ends_yes and ends_no:
                return path, True
            if ends_yes:                         # whoever continues did NOT enter the if
                state.clear(); state.update(state_no)
                path = path + [Not(formula)]
            elif ends_no:                        # whoever continues DID enter the if
                state.clear(); state.update(state_yes)
                path = path + [formula]
            else:                                # branches merge again
                for name in set(state_yes) | set(state_no):
                    if name in state_yes and name in state_no:
                        if state_yes[name] is state_no[name]:
                            state[name] = state_yes[name]
                        else:
                            try:
                                state[name] = If(formula, state_yes[name], state_no[name])
                            except Exception:
                                state.pop(name, None)
                    else:
                        state.pop(name, None)

        elif isinstance(node, ast.Return):
            hunt_divisions(node.value, state, path, locks)
            # "reach this line" is itself a goal: the path that gets here.
            # For a license check, the deepest return is reachable only by a
            # valid serial - exactly the input Z3 can forge and fuzzing can't.
            if top:
                locks.append(("reach: " + ast.unparse(node), list(path), "reach"))
            return path, True
        elif isinstance(node, ast.Raise):
            return path, True
        elif isinstance(node, ast.Expr):
            hunt_divisions(node.value, state, path, locks)
        elif isinstance(node, ast.Pass):
            pass
        else:
            for name in stored_names(node):
                state.pop(name, None)
            skipped.append(ast.unparse(node).splitlines()[0])

    return path, False


def read_locks(function):
    """
    Read the target's code and return:
      - the parameter names (e.g. ["serial"])
      - the locks: list of (description, Z3 formulas, kind)
      - the lines SESAMO could not translate
    """
    source = textwrap.dedent(inspect.getsource(function))
    definition = ast.parse(source).body[0]
    params = [a.arg for a in definition.args.args]

    state = {name: Int(name) for name in params}
    locks, skipped = [], []
    walk(definition.body, state, [], locks, skipped, top=True)
    return params, locks, skipped


# =====================================================================
# PART 3 - Z3 (the locksmith)
# =====================================================================

def find_key(params, formulas, timeout_ms=3000):
    """Ask Z3 for inputs making every formula true. None if impossible."""
    solver = Solver()
    solver.set("timeout", timeout_ms)
    for f in formulas:
        solver.add(f)
    if solver.check() == sat:
        model = solver.model()
        return tuple(model.eval(Int(name), model_completion=True).as_long() for name in params)
    return None


# =====================================================================
# PART 4 - SESAMO (makes them work together)
# =====================================================================

def seed_input(arity):
    return tuple([0] * arity)


def sesamo(function, rounds=5000, use_z3=True, seed=None, verbose=True):
    """
    Hunt for inputs that crash 'function' (an AssertionError counts).
    With use_z3=False only the fuzzer works - used for the comparison.
    Returns a report dict.
    """
    start = time.perf_counter()
    fz = Fuzzer(function, seed=seed, verbose=verbose)
    keys_used, skipped = [], []

    fz.say("PHASE 1 - the fuzzer alone")
    fz.test(seed_input(fz.arity))
    fz.fuzz(rounds)
    if fz.crashes:
        for text, _, _ in []:
            pass

    if use_z3:
        fz.say("\nPHASE 2 - read the locks, call Z3")
        params, locks, skipped = read_locks(function)
        opened_new = False
        for text, formulas, kind in locks:
            key = find_key(params, formulas)
            if key is None:
                fz.door_log[text] = ("walled", None)
                fz.say(" ", pad(text), "-> walled, no key exists")
                continue
            fz.say(" ", pad(text), "-> key:", fmt(key))
            keys_used.append((text, key))
            had = len(fz.crashes)
            if fz.test(key):
                opened_new = True
                fz.door_log[text] = ("Z3", fz.runs)
            if len(fz.crashes) > had:
                fz.door_log[text] = ("Z3", fz.runs)

        if opened_new and not fz.crashes:
            fz.say("\nPHASE 3 - the fuzzer restarts from the new keys")
            fz.fuzz(max(rounds // 5, 1))

    report = {
        "crashes": fz.crashes,
        "runs": fz.runs,
        "runs_to_first_crash": fz.runs_to_first_crash,
        "lines": sorted(fz.seen_lines),
        "keys": keys_used,
        "skipped": skipped,
        "seconds": time.perf_counter() - start,
    }
    if verbose:
        print("\nLines reached:", report["lines"])
        print("Crashing inputs:", [fmt(a) for a, _ in fz.crashes])
        if skipped:
            print("Lines SESAMO could not translate for Z3:", skipped)
    return report


def pad(text, width=34):
    return text if len(text) >= width else text + " " * (width - len(text))


# =====================================================================
# THE DOOR MAP (the part that makes the README)
# =====================================================================

def door_map(function, rounds=5000, seed=1):
    """
    Run SESAMO quietly, then print the target as a maze of doors,
    showing who opened each one: the fuzzer, Z3, or nobody (walled).
    This is the picture that goes at the top of the README.
    """
    params, locks, _ = read_locks(function)

    # let the fuzzer run alone first, to see which doors it opens by itself
    solo = Fuzzer(function, seed=seed, verbose=False)
    solo.test(seed_input(solo.arity))
    for _ in range(rounds):
        solo.test(solo.mutate(solo.chance.choice(solo.corpus)))

    print("  SESAMO door map:  " + function.__name__ + "   (" + ", ".join(params) + ")")
    print("  " + "=" * 58)
    for text, formulas, kind in locks:
        key = find_key(params, formulas)
        if key is None:
            who, note = "[walled]", "Z3 proves it can never open"
        elif satisfied_by(params, formulas, solo):
            who, note = "[fuzzer]", "opened by random mutation"
        else:
            who = "[  Z3  ]"
            note = "forged " + fmt(key)
            if kind in ("crash", "div-by-zero"):
                note += "   ==> CRASH"
            elif kind == "assert":
                note += "   ==> BROKEN PROMISE"
            elif kind == "reach":
                note += "   ==> REACHED"
        print(f"  {who}  {pad(text, 36)} {note}")
    print("  " + "=" * 58)
    print("  [fuzzer] a dumb random fuzzer already gets here")
    print("  [  Z3  ] only the solver can craft this input")
    print("  [walled] no input can reach it - and Z3 proves it")
    print()


def satisfied_by(params, formulas, fuzzer):
    """True if any input the lone fuzzer kept satisfies this lock's formulas."""
    for args in fuzzer.corpus:
        solver = Solver()
        for name, value in zip(params, args):
            solver.add(Int(name) == value)
        for f in formulas:
            solver.add(f)
        if solver.check() == sat:
            return True
    return False


# =====================================================================
# COMMAND LINE
# =====================================================================

def load_target(path, name="target"):
    spec = importlib.util.spec_from_file_location("target_module", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return getattr(module, name)


def main():
    parser = argparse.ArgumentParser(description="SESAMO - fuzzer + Z3 bug hunter")
    parser.add_argument("file", help="a .py file containing a function named 'target'")
    parser.add_argument("--rounds", type=int, default=5000, help="fuzzer rounds (default 5000)")
    parser.add_argument("--fuzzer-only", action="store_true", help="do not use Z3")
    parser.add_argument("--map", action="store_true", help="print the door map and exit")
    parser.add_argument("--seed", type=int, default=None, help="random seed, to repeat a run")
    args = parser.parse_args()

    target = load_target(args.file)
    if args.map:
        door_map(target, rounds=args.rounds, seed=args.seed or 1)
        return
    report = sesamo(target, rounds=args.rounds, use_z3=not args.fuzzer_only, seed=args.seed)
    sys.exit(1 if report["crashes"] else 0)


if __name__ == "__main__":
    main()
