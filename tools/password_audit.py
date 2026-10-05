"""Password strength auditor: entropy estimate, policy checks and common-pattern detection.

Nothing is stored or sent anywhere. Input is read with getpass so it is not echoed.

Usage:
    python password_audit.py            # interactive prompt
"""
import getpass
import math
import re
import string

COMMON = {
    "123456", "password", "123456789", "12345678", "qwerty", "azerty", "111111", "abc123",
    "password1", "iloveyou", "admin", "welcome", "letmein", "monkey", "dragon", "football",
}
KEYBOARD_RUNS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "azertyuiop", "1234567890")


def charset_size(pw):
    size = 0
    if any(c in string.ascii_lowercase for c in pw):
        size += 26
    if any(c in string.ascii_uppercase for c in pw):
        size += 26
    if any(c in string.digits for c in pw):
        size += 10
    if any(c in string.punctuation for c in pw):
        size += len(string.punctuation)
    if any(ord(c) > 127 for c in pw):
        size += 100
    return size


def entropy_bits(pw):
    return round(len(pw) * math.log2(charset_size(pw)), 1) if pw else 0.0


def findings(pw):
    issues = []
    low = pw.lower()
    if len(pw) < 12:
        issues.append("shorter than 12 characters")
    if low in COMMON or re.sub(r"\d+$", "", low) in COMMON:
        issues.append("appears in common-password lists")
    if re.search(r"(.)\1{2,}", pw):
        issues.append("contains a character repeated 3+ times")
    for run in KEYBOARD_RUNS:
        for i in range(len(run) - 3):
            if run[i:i + 4] in low:
                issues.append(f"contains keyboard sequence '{run[i:i + 4]}'")
                break
    if re.search(r"(19|20)\d{2}", pw):
        issues.append("contains a year (easy to guess)")
    if sum(map(bool, [re.search(r"[a-z]", pw), re.search(r"[A-Z]", pw),
                      re.search(r"\d", pw), re.search(r"[^\w\s]", pw)])) < 3:
        issues.append("uses fewer than 3 character classes")
    return issues


def rating(pw):
    bits = entropy_bits(pw)
    penalty = 15 * len(findings(pw))
    score = max(bits - penalty, 0)
    if score >= 80:
        return "STRONG"
    if score >= 60:
        return "GOOD"
    if score >= 40:
        return "WEAK"
    return "VERY WEAK"


def crack_time(bits, guesses_per_second=1e10):
    seconds = 2 ** bits / 2 / guesses_per_second
    for unit, size in (("years", 31_536_000), ("days", 86_400), ("hours", 3_600), ("minutes", 60)):
        if seconds >= size:
            return f"~{seconds / size:,.0f} {unit}"
    return "< 1 minute"


def main():
    pw = getpass.getpass("Password to audit (hidden): ")
    bits = entropy_bits(pw)
    print(f"\nLength        : {len(pw)}")
    print(f"Entropy       : {bits} bits")
    print(f"Offline crack : {crack_time(bits)} at 10 billion guesses/s")
    print(f"Rating        : {rating(pw)}")
    for issue in findings(pw):
        print(f"  ! {issue}")


if __name__ == "__main__":
    main()
