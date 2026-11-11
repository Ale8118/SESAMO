# 🗝️ SESAMO

*Open sesame: a tiny bug-hunter that talks a fuzzer and a theorem prover into working together.*

![tests](https://img.shields.io/badge/tests-13%20passing-brightgreen)
![python](https://img.shields.io/badge/python-3.9%2B-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)
![deps](https://img.shields.io/badge/deps-z3--solver-orange)

A program is a maze. Most corridors are open and a clumsy robot bumping into walls will eventually wander through them. But some doors are **locked with an exact combination** - `if serial == 1086743` - and the robot can rattle the handle until the heat death of the universe without ever guessing the code.

SESAMO sends in the clumsy robot (a **coverage-guided fuzzer**) to explore the easy corridors. The moment it hits a locked door, SESAMO reads the lock straight off the code, hands it to a **theorem prover** (Z3), and gets back the key. Robot walks through, keeps exploring, hits the next locked door, calls the locksmith again. Rinse, repeat, find the bug.

The grown-up name for this is **concolic testing**. SESAMO is a small, readable, thoroughly commented version you can actually understand in an afternoon.

---

## See it in one picture

Point SESAMO at a toy software-license check and ask it to draw the maze:

```
$ python sesamo.py examples/02_license_key.py --map

  SESAMO door map:  target   (serial)
  ==========================================================
  [fuzzer]  serial < 100000                      opened by random mutation
  [  Z3  ]  serial % 97 != 42                    forged (100007)
  [  Z3  ]  block % 1000 != 123                  forged (100049)
  [  Z3  ]  reach: return accepted               forged (108973)   ==> REACHED
  ==========================================================
  [fuzzer] a dumb random fuzzer already gets here
  [  Z3  ] only the solver can craft this input
  [walled] no input can reach it - and Z3 proves it
```

That last line is the punchline: no human guesses a valid serial, and no fuzzer stumbles on one either. SESAMO reads the three arithmetic checks and **Z3 forges `108973`** - a serial the real code accepts. That is why you should never roll your own license math.

---

## The results

Five example targets, each hiding a bug behind an exact condition. The lone fuzzer gets a **ten times bigger** budget and still comes home empty-handed. (Reproduce with `python compare.py`.)

| example | lone fuzzer (50,000 rounds) | SESAMO (5,000 + Z3) |
|---|---|---|
| `01_warmup_narrow_door` - one magic number | **never** | 5/5 ✅ |
| `02_license_key` - forge a valid serial | **never** | 5/5 ✅ |
| `03_checksum_forgery` - collide a home-made hash | **never** | 5/5 ✅ |
| `04_game_damage` - a frame-perfect exploit | **never** | 5/5 ✅ |
| `05_hidden_division` - an unplanned divide-by-zero | **never** | 5/5 ✅ |
| `06_walled_door` - a bug that *can't* happen | never (correct) | never, **and Z3 proves why** |

"Never" is not an exaggeration: those doors are one value wide in a space of billions.

---

## Quick start

```bash
pip install -r requirements.txt        # just z3-solver and pytest

python sesamo.py examples/05_hidden_division.py       # hunt for the bug
python sesamo.py examples/02_license_key.py --map     # draw the maze
python compare.py                                     # the results table
python -m pytest                                      # prove it finds the known bugs
```

Write your own target: any file with a function named `target` taking one or more integers. A "crash" is any exception it raises - and `assert` is your friend:

```python
def target(attack, armor, combo):
    damage = attack * combo - armor
    assert damage >= 0        # SESAMO hunts for the input that breaks this promise
    return damage
```

---

## How it works, in five honest pieces

1. **Coverage** (`Fuzzer.coverage`) - run the target with a "camera" (`sys.settrace`) that notes every line it touches. Different inputs light up different lines; that is the compass.
2. **The fuzzer** (`Fuzzer.fuzz`) - throw inputs at the target, keep the ones that light up *new* lines, mutate those to go deeper. Fast, dumb, relentless.
3. **The lock reader** (`read_locks`) - walk the code with Python's `ast`, carrying a notebook of what each variable is worth symbolically (`x = n*2` becomes the formula `n*2`). Every `if`, every `assert`, every division becomes a **lock** plus the **path** of conditions needed to reach it.
4. **The locksmith** (`find_key`) - hand the lock's formulas to Z3. It either forges an input that opens it, or **proves no input can** (`unsat`) - a certainty no amount of fuzzing can give you.
5. **SESAMO** (`sesamo`) - fuzz until stuck, then let Z3 open the doors fuzzing couldn't, feed the keys back to the fuzzer, repeat.

Everything lives in one readable file, `sesamo.py`, with comments that use the same maze-and-keys language as this README.

---

## Limits (a.k.a. where the maze beats us)

Being honest about this is half the point of the project:

- **Integers only.** No strings, floats, lists, or objects (yet). The ideas extend; the code doesn't, on purpose, to stay readable.
- **No loops.** SESAMO reads straight-line code with branches. A `while` is skipped and its variables forgotten. Real symbolic execution fights "path explosion" here, and so would we.
- **Z3 has its own walls.** Give it a real hash like SHA-256 instead of the toy checksum in `examples/03`, and it will shrug - those functions are *designed* to be un-invertible. That is cryptography working as intended, and SESAMO's failure on it is a feature of the world, not a bug in the tool.
- **The hand-off is naive.** SESAMO always fuzzes a fixed number of rounds before calling Z3. Deciding *when* the solver is worth its cost is an open, genuinely interesting problem - and the natural next thing to build.

---

## Roadmap

- [ ] A smarter rule for *when* to call Z3 instead of a fixed round count
- [ ] Strings (Z3 speaks them too)
- [ ] Point it at functions written by an AI and count the bugs

---

## About this project

I built SESAMO to learn how fuzzing and constraint solving actually work, by assembling it one piece at a time rather than importing a finished tool. I wrote it with an AI assistant as a tutor - the design decisions, the examples, and the understanding are mine; some of the typing was not. I'd rather say that plainly than pretend otherwise.

MIT licensed. Run it only on your own code or code written to be tested.
