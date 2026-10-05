"""File integrity monitor: build a SHA-256 baseline of a folder, then detect changes.

Usage:
    python file_integrity.py baseline  C:\\important\\folder  -o baseline.json
    python file_integrity.py check     C:\\important\\folder  -b baseline.json
"""
import argparse
import hashlib
import json
import os
import sys


def sha256(path, chunk=1 << 20):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def snapshot(root):
    result = {}
    for dirpath, _, files in os.walk(root):
        for name in files:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            try:
                result[rel] = sha256(full)
            except OSError as e:
                print(f"skip {rel}: {e}", file=sys.stderr)
    return result


def compare(baseline, current):
    added = sorted(set(current) - set(baseline))
    removed = sorted(set(baseline) - set(current))
    modified = sorted(p for p in set(baseline) & set(current) if baseline[p] != current[p])
    return {"added": added, "removed": removed, "modified": modified}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("mode", choices=["baseline", "check"])
    ap.add_argument("folder")
    ap.add_argument("-o", "--output", default="baseline.json")
    ap.add_argument("-b", "--baseline", default="baseline.json")
    a = ap.parse_args()

    if a.mode == "baseline":
        snap = snapshot(a.folder)
        with open(a.output, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2, sort_keys=True)
        print(f"Baseline of {len(snap)} files written to {a.output}")
        return

    with open(a.baseline, encoding="utf-8") as f:
        diff = compare(json.load(f), snapshot(a.folder))
    total = sum(map(len, diff.values()))
    for kind, paths in diff.items():
        for p in paths:
            print(f"[{kind.upper():8}] {p}")
    print("Integrity OK - no changes." if total == 0 else f"{total} change(s) detected.")
    sys.exit(1 if total else 0)


if __name__ == "__main__":
    main()
