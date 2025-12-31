#!/usr/bin/env python3
import itertools
import os
import re
import string
import sys
import time

TLD_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")  # loose DNS label check
LABEL_ALLOWED_RE = re.compile(r"^[a-z+]+$")  # template label: lowercase letters and +

def human_int(n: int) -> str:
    return f"{n:,}"

def human_bytes(num: float) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num < 1024.0:
            return f"{num:,.2f} {unit}"
        num /= 1024.0
    return f"{num:,.2f} PB"

def render_bar(done: int, total: int, width: int = 30) -> str:
    if total <= 0:
        return "[" + ("#" * width) + "]"
    frac = min(max(done / total, 0.0), 1.0)
    filled = int(frac * width)
    return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"

def normalize_tld(s: str) -> str:
    s = s.strip().lower()
    if s.startswith("."):
        s = s[1:]
    return s

def parse_template(raw: str):
    """
    Accepts:
      - "a++++" (label only)
      - "a++++.com" (full domain; single-label TLD only)
    Returns (label_template, tld_or_none).
    """
    s = raw.strip().lower()
    if not s:
        return None, None

    if "." in s:
        label, tld = s.rsplit(".", 1)
        return label, tld
    return s, None

def main() -> int:
    # Ask for N
    try:
        n_str = input("How many Ls (length of domain label)? e.g., 5 for LLLLL: ").strip()
        n = int(n_str)
    except ValueError:
        print("Please enter a valid integer.", file=sys.stderr)
        return 2

    if n <= 0:
        print("Length must be >= 1.", file=sys.stderr)
        return 2
    if n > 8:
        print("Warning: N > 8 is astronomically large (26^N). This will likely be impractical.", file=sys.stderr)

    # Template with default of "+" * n
    default_template = "+" * n
    template_raw = input(
        f"Template (use '+' as wildcard). Example: a{('+' * (n - 1))} or a{('+' * (n - 1))}.com\n"
        f"Press Enter for default ({default_template}): "
    ).strip()
    if not template_raw:
        template_raw = default_template

    template_label, template_tld = parse_template(template_raw)
    if template_label is None:
        print("Invalid template input.", file=sys.stderr)
        return 2

    # Validate label template
    if len(template_label) != n:
        print(f"Template label length ({len(template_label)}) must match N ({n}).", file=sys.stderr)
        return 2
    if not LABEL_ALLOWED_RE.match(template_label):
        print("Template label may only contain letters a-z and '+'.", file=sys.stderr)
        return 2

    # Ask for TLD unless provided in template
    if template_tld:
        tld = normalize_tld(template_tld)
    else:
        tld = normalize_tld(input("Enter TLD (e.g., com, net, org): "))

    if not tld or not TLD_RE.match(tld):
        print(
            "Invalid TLD format. Examples: com, net (NOTE: this script expects a single label like 'com').",
            file=sys.stderr,
        )
        return 2

    letters = string.ascii_lowercase

    wildcard_positions = [i for i, ch in enumerate(template_label) if ch == "+"]
    k = len(wildcard_positions)
    total = 26 ** k

    # Output filename: replace + with 'l' to keep it readable
    safe_label = template_label.replace("+", "l")
    out_file = f"{safe_label}.{tld}.txt"

    # Example domain
    example_label = list(template_label)
    for i in wildcard_positions:
        example_label[i] = "a"
    example_domain = "".join(example_label) + f".{tld}"

    # Rough file size estimate
    est_bytes = total * (n + 2 + len(tld))

    print(f"\nWill generate: {human_int(total)} domains")
    print(f"Example: {example_domain}")
    print(f"Output file: {out_file}")
    print(f"Estimated minimum file size: ~{human_bytes(est_bytes)} (very rough)\n")

    if os.path.exists(out_file):
        ans = input(f"File '{out_file}' already exists. Overwrite? (y/N): ").strip().lower()
        if ans != "y":
            print("Aborted.")
            return 0

    update_every = 10_000   # progress redraw frequency
    flush_every = 200_000   # flush file buffer frequency

    start = time.time()
    done = 0
    last_print = 0

    try:
        with open(out_file, "w", encoding="utf-8", newline="\n") as f:
            chunk = []
            chunk_size = 50_000
            suffix = f".{tld}\n"

            # Generate only wildcard combinations (if k == n, this is "all combos")
            for combo in itertools.product(letters, repeat=k):
                label_chars = list(template_label)
                for pos, letter in zip(wildcard_positions, combo):
                    label_chars[pos] = letter

                chunk.append("".join(label_chars) + suffix)
                done += 1

                if len(chunk) >= chunk_size:
                    f.write("".join(chunk))
                    chunk.clear()

                if done - last_print >= update_every or done == total:
                    elapsed = time.time() - start
                    rate = done / elapsed if elapsed > 0 else 0.0
                    eta = (total - done) / rate if rate > 0 else float("inf")
                    bar = render_bar(done, total, width=32)
                    pct = (done / total) * 100 if total else 100.0
                    msg = (
                        f"\r{bar} {pct:6.2f}%  "
                        f"{human_int(done)}/{human_int(total)}  "
                        f"{rate:,.0f}/s  ETA {eta:,.0f}s"
                    )
                    sys.stdout.write(msg)
                    sys.stdout.flush()
                    last_print = done

                if done % flush_every == 0:
                    f.flush()

            if chunk:
                f.write("".join(chunk))

        elapsed = time.time() - start
        sys.stdout.write("\n")
        print(f"Done in {elapsed:,.2f}s. Wrote {human_int(total)} domains to '{out_file}'.")
        return 0

    except KeyboardInterrupt:
        sys.stdout.write("\nInterrupted by user.\n")
        print(f"Progress: {human_int(done)}/{human_int(total)} written so far.")
        print(f"Partial output may exist in '{out_file}'.")
        return 130

if __name__ == "__main__":
    raise SystemExit(main())
