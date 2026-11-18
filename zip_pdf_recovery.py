#!/usr/bin/env python3
"""
zip_pdf_recovery.py
CSL-G17 · RTU 7CS4-22 Experiment 3

Multithreaded Dictionary & Brute-Force Password Recovery Tool
for self-created protected ZIP and PDF files.

Modes
-----
  dict   – Dictionary attack with rule-based mutation engine
  brute  – Exhaustive combinatorial brute-force attack

Both modes use ``concurrent.futures.ThreadPoolExecutor``, in-memory
``io.BytesIO`` buffering (zero disk I/O contention across threads),
and ``threading.Event`` early termination the instant a worker
finds the matching password.

Usage
-----
  # Dictionary on a ZIP
  python zip_pdf_recovery.py -f test_targets/own_dict.zip -m dict \\
         -w test_targets/wordlist.txt -W 4

  # Brute-force a 4-digit PIN
  python zip_pdf_recovery.py -f test_targets/own_pin.zip -m brute \\
         -c digits --min-len 4 --max-len 4 -W 8

  # Dictionary on a PDF
  python zip_pdf_recovery.py -f test_targets/own_rc4.pdf -m dict \\
         -w test_targets/wordlist.txt -W 4
"""

from __future__ import annotations

import argparse
import io
import itertools
import os
import sys
import threading
import time
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, Iterator

try:
    import pypdf
except ImportError:
    pypdf = None


# ═══════════════════════════════════════════════════════════════════════
#  File-type detection
# ═══════════════════════════════════════════════════════════════════════

def detect_type(path: str) -> str:
    """Return ``'zip'`` or ``'pdf'`` based on file extension."""
    ext = os.path.splitext(path)[1].lower()
    if ext == '.zip':
        return 'zip'
    if ext == '.pdf':
        return 'pdf'
    raise ValueError(f"Unsupported file extension: {ext}")


# ═══════════════════════════════════════════════════════════════════════
#  Password testers  (operate on in-memory bytes → zero disk I/O)
# ═══════════════════════════════════════════════════════════════════════

def try_zip_password(data: bytes, password: str) -> bool:
    """Test *password* against an in-memory ZIP archive."""
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                zf.read(name, pwd=password.encode('utf-8'))
        return True
    except (RuntimeError, zipfile.BadZipFile, zlib.error, KeyError,
            Exception):
        return False


def try_pdf_password(data: bytes, password: str) -> bool:
    """Test *password* against an in-memory PDF document."""
    if pypdf is None:
        raise RuntimeError(
            "pypdf is required for PDF recovery: pip install pypdf")
    try:
        reader = pypdf.PdfReader(io.BytesIO(data))
        if not reader.is_encrypted:
            return False
        rc = reader.decrypt(password)
        if rc > 0:
            # Force a page read to verify real access
            _ = len(reader.pages)
            return True
        return False
    except Exception:
        return False


_TESTERS: dict[str, Callable[[bytes, str], bool]] = {
    'zip': try_zip_password,
    'pdf': try_pdf_password,
}


# ═══════════════════════════════════════════════════════════════════════
#  Dictionary + Rule-Mutation Engine  (--mode dict)
# ═══════════════════════════════════════════════════════════════════════

_LEET = str.maketrans({
    'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$',
})
_SUFFIXES = ('', '123', '@123', '2026', '99', '!')


def mutate(word: str) -> Iterator[str]:
    """Yield rule-expanded variants of a single base word.

    Transformations applied:
      • lowercase / UPPERCASE / TitleCase
      • leetspeak on lower & title forms
      • each form × six common suffixes
    """
    forms = [
        word.lower(),
        word.upper(),
        word.title(),
        word.lower().translate(_LEET),
        word.title().translate(_LEET),
    ]
    # Deduplicate forms (e.g. single-char words)
    seen: set[str] = set()
    for base in forms:
        for suffix in _SUFFIXES:
            candidate = base + suffix
            if candidate not in seen:
                seen.add(candidate)
                yield candidate


def load_wordlist(path: str) -> list[str]:
    """Read *wordlist.txt* and expand every word with mutation rules.

    Returns a deduplicated list ready for the recovery runner.
    """
    seen: set[str] = set()
    result: list[str] = []
    with open(path, 'r', errors='ignore') as fh:
        for line in fh:
            word = line.strip()
            if not word:
                continue
            for variant in mutate(word):
                if variant not in seen:
                    seen.add(variant)
                    result.append(variant)
    return result


# ═══════════════════════════════════════════════════════════════════════
#  Exhaustive Brute-Force Engine  (--mode brute)
# ═══════════════════════════════════════════════════════════════════════

CHARSETS: dict[str, str] = {
    'digits':      '0123456789',
    'lower':       'abcdefghijklmnopqrstuvwxyz',
    'alnum_lower': 'abcdefghijklmnopqrstuvwxyz0123456789',
    'alnum':       ('abcdefghijklmnopqrstuvwxyz'
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'),
    'full':        ('abcdefghijklmnopqrstuvwxyz'
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
                    '0123456789!@#$%^&*()'),
}


def brute_candidates(charset: str, min_len: int,
                     max_len: int) -> Iterator[str]:
    """Yield every candidate from ``charset^min_len … charset^max_len``."""
    for length in range(min_len, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            yield ''.join(combo)


# ═══════════════════════════════════════════════════════════════════════
#  Threaded Recovery Runner
# ═══════════════════════════════════════════════════════════════════════

def _chunked(iterable: Iterable[str], size: int) -> Iterator[list[str]]:
    """Yield successive chunks of *size* from *iterable*."""
    batch: list[str] = []
    for item in iterable:
        batch.append(item)
        if len(batch) == size:
            yield batch
            batch = []
    if batch:
        yield batch


def recover(file_data: bytes,
            file_type: str,
            candidates: Iterable[str],
            max_workers: int = 4,
            chunk_size: int = 250,
            quiet: bool = False):
    """Run threaded password recovery.

    Parameters
    ----------
    file_data : bytes
        Entire target file loaded in memory.
    file_type : str
        ``'zip'`` or ``'pdf'``.
    candidates : iterable of str
        Password candidates (list or lazy generator).
    max_workers : int
        Thread-pool size.
    chunk_size : int
        Passwords per ``Future`` batch.
    quiet : bool
        Suppress live progress.

    Returns
    -------
    tuple[str | None, int, float]
        ``(password, candidates_tried, elapsed_seconds)``
    """
    tester       = _TESTERS[file_type]
    found_event  = threading.Event()
    result_pwd   = [None]           # mutable container for cross-thread
    counter      = [0]
    counter_lock = threading.Lock()

    def check_batch(batch: list[str]):
        local = 0
        for pwd in batch:
            if found_event.is_set():
                break
            local += 1
            if tester(file_data, pwd):
                found_event.set()
                result_pwd[0] = pwd
                break
        with counter_lock:
            counter[0] += local

    t0 = time.perf_counter()

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = []
        for batch in _chunked(candidates, chunk_size):
            if found_event.is_set():
                break
            futures.append(pool.submit(check_batch, batch))

        for fut in as_completed(futures):
            fut.result()            # propagate any exceptions

    elapsed = time.perf_counter() - t0
    return result_pwd[0], counter[0], elapsed


# ═══════════════════════════════════════════════════════════════════════
#  CLI Interface
# ═══════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog='zip_pdf_recovery',
        description=('CSL-G17 · Multithreaded Dictionary & Brute-Force '
                     'Password Recovery for ZIP & PDF'),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument('--file', '-f', required=True,
                   help='Target ZIP or PDF file')
    p.add_argument('--mode', '-m', choices=['dict', 'brute'], required=True,
                   help='Attack mode')
    p.add_argument('--wordlist', '-w',
                   help='Path to wordlist (dict mode)')
    p.add_argument('--charset', '-c', choices=list(CHARSETS),
                   default='digits',
                   help='Character set (brute mode, default: digits)')
    p.add_argument('--min-len', type=int, default=1,
                   help='Min password length (brute mode, default: 1)')
    p.add_argument('--max-len', type=int, default=4,
                   help='Max password length (brute mode, default: 4)')
    p.add_argument('--workers', '-W', type=int, default=4,
                   help='ThreadPoolExecutor workers (default: 4)')
    p.add_argument('--chunk-size', type=int, default=250,
                   help='Batch size per Future (default: 250)')
    p.add_argument('--quiet', '-q', action='store_true',
                   help='Suppress banner')
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)

    # ── validate inputs ──────────────────────────────────────────────
    if not os.path.isfile(args.file):
        print(f"[!] File not found: {args.file}", file=sys.stderr)
        sys.exit(1)

    file_type = detect_type(args.file)
    if file_type == 'pdf' and pypdf is None:
        print("[!] pypdf required for PDF recovery: pip install pypdf",
              file=sys.stderr)
        sys.exit(1)

    # ── load file entirely into memory ────────────────────────────────
    with open(args.file, 'rb') as fh:
        file_data = fh.read()

    if not args.quiet:
        print()
        print("═" * 62)
        print("  CSL-G17 · Password Recovery")
        print("═" * 62)
        print(f"  Target  : {args.file}  "
              f"({file_type.upper()}, {len(file_data):,} bytes)")
        print(f"  Mode    : {args.mode}")
        print(f"  Workers : {args.workers}")

    # ── build candidate stream ────────────────────────────────────────
    if args.mode == 'dict':
        if not args.wordlist:
            print("[!] --wordlist/-w is required for dict mode",
                  file=sys.stderr)
            sys.exit(1)
        candidates = load_wordlist(args.wordlist)
        if not args.quiet:
            print(f"  Candidates : {len(candidates):,} (mutated)")
    else:
        cs = CHARSETS[args.charset]
        total_space = sum(len(cs) ** L
                         for L in range(args.min_len, args.max_len + 1))
        if not args.quiet:
            print(f"  Charset : {args.charset} ({len(cs)} chars), "
                  f"length {args.min_len}–{args.max_len}")
            print(f"  Search space : {total_space:,}")
        candidates = brute_candidates(cs, args.min_len, args.max_len)

    if not args.quiet:
        print("─" * 62)
        print("  Searching …")

    # ── run recovery ──────────────────────────────────────────────────
    pwd, tried, elapsed = recover(
        file_data, file_type, candidates,
        max_workers=args.workers,
        chunk_size=args.chunk_size,
        quiet=args.quiet,
    )

    throughput = tried / elapsed if elapsed > 0 else 0.0

    # ── report ────────────────────────────────────────────────────────
    if not args.quiet:
        print()
    if pwd is not None:
        print(f"  ✅ PASSWORD FOUND : {pwd}")
    else:
        print("  ❌ Password NOT found in candidate space.")
    print(f"  Candidates tried : {tried:,}")
    print(f"  Elapsed time     : {elapsed:.3f} s")
    print(f"  Throughput       : {throughput:,.1f} pwd/s")
    if not args.quiet:
        print("═" * 62)
        print()


if __name__ == '__main__':
    main()
