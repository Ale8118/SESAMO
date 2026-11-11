"""
A bug nobody planted on purpose - just an innocent-looking fee calculation.

The last digits of a case number encode the remaining months; the installment
divides by them. For one precise case number the remaining months hit zero and
the whole thing blows up. SESAMO treats every division as a door and asks Z3
when the divisor can be zero.
"""


def target(case_number):
    if case_number < 0:
        return "error"
    months = case_number % 500
    remaining = months - 137
    if case_number > 2000000:
        installment = 1000 / remaining
        return installment
    return 0
