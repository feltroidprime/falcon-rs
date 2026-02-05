#!/usr/bin/env python3
"""Parse NIST Falcon-512 KAT file and output JSON test vectors."""
import json
import sys

def parse_kat_file(filepath: str) -> list[dict]:
    """Parse NIST KAT .rsp file."""
    vectors = []
    current = {}

    with open(filepath, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            if line.startswith('count = '):
                if current:
                    vectors.append(current)
                current = {'count': int(line.split(' = ')[1])}
            elif ' = ' in line:
                key, value = line.split(' = ', 1)
                if key == 'mlen' or key == 'smlen':
                    current[key] = int(value)
                else:
                    current[key] = value

    if current:
        vectors.append(current)

    return vectors

def main():
    if len(sys.argv) < 2:
        print("Usage: python parse_nist_kat.py <kat_file.rsp> [count]", file=sys.stderr)
        sys.exit(1)

    filepath = sys.argv[1]
    max_count = int(sys.argv[2]) if len(sys.argv) > 2 else 10

    vectors = parse_kat_file(filepath)[:max_count]
    print(json.dumps(vectors, indent=2))

if __name__ == '__main__':
    main()
