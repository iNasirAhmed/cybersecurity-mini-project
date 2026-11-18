#!/usr/bin/env python3
"""
benchmark_suite.py
CSL-G17 · RTU 7CS4-22 Experiment 3

Automated performance benchmark runner that measures recovery
throughput (pwd/s) and parallel speedup across 1, 2, 4, 8, and 16
workers on all four self-created test targets.

Output
------
  • Formatted comparison table  (stdout)
  • benchmark_chart.png         (matplotlib grouped bar chart)
"""

from __future__ import annotations

import os
import subprocess
import sys
import time

# Ensure project root is importable
PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, PROJECT_DIR)

from zip_pdf_recovery import (
    CHARSETS,
    brute_candidates,
    load_wordlist,
    recover,
)

WORKER_COUNTS = [1, 2, 4, 8, 16]
TARGET_DIR    = os.path.join(PROJECT_DIR, 'test_targets')


# ═══════════════════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════════════════

def ensure_targets():
    """Generate test files if they don't already exist."""
    if not os.path.isfile(os.path.join(TARGET_DIR, 'own_dict.zip')):
        print("[*] Test targets missing – generating …\n")
        subprocess.check_call([
            sys.executable,
            os.path.join(PROJECT_DIR, 'generate_test_files.py'),
        ])
        print()


def load_file(name: str) -> bytes:
    with open(os.path.join(TARGET_DIR, name), 'rb') as f:
        return f.read()


# ═══════════════════════════════════════════════════════════════════════
#  Single-target benchmark
# ═══════════════════════════════════════════════════════════════════════

def benchmark_target(label, file_data, file_type, candidates_fn,
                     worker_counts):
    """Run recovery at every worker count; return results dict."""
    results: dict[int, dict] = {}
    for w in worker_counts:
        candidates = candidates_fn()          # fresh each run
        pwd, tried, elapsed = recover(
            file_data, file_type, candidates,
            max_workers=w, chunk_size=250, quiet=True,
        )
        tput = tried / elapsed if elapsed > 0 else 0.0
        results[w] = dict(password=pwd, tried=tried,
                          elapsed=elapsed, throughput=tput)
        ok = f"✓ {pwd}" if pwd else "✗"
        print(f"    W={w:<2d}  tried={tried:>8,}  "
              f"time={elapsed:8.3f}s  "
              f"tput={tput:>11,.1f} pwd/s  {ok}")
    return results


# ═══════════════════════════════════════════════════════════════════════
#  Result formatting
# ═══════════════════════════════════════════════════════════════════════

def print_summary_table(all_results):
    """Print a formatted comparison table to stdout."""
    col_w = 14
    hdr = f"{'Target':<28s}"
    for w in WORKER_COUNTS:
        hdr += f"{'W=' + str(w):>{col_w}s}"
    hdr += f"{'Speedup':>{col_w}s}"

    print()
    print("═" * len(hdr))
    print("  CSL-G17 · Benchmark Results  (throughput in pwd/s)")
    print("═" * len(hdr))
    print(hdr)
    print("─" * len(hdr))

    for label, results in all_results.items():
        row = f"{label:<28s}"
        base = results[1]['throughput']
        base = base if base > 0 else 1.0
        for w in WORKER_COUNTS:
            t = results[w]['throughput']
            row += f"{t:>{col_w},.1f}"
        best = results[WORKER_COUNTS[-1]]['throughput']
        speedup = best / base if base > 0 else 0.0
        row += f"{speedup:>{col_w - 1}.2f}x"
        print(row)

    print("═" * len(hdr))


# ═══════════════════════════════════════════════════════════════════════
#  Chart generation
# ═══════════════════════════════════════════════════════════════════════

def save_chart(all_results, path: str):
    """Generate and save a grouped bar chart with matplotlib."""
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        print("[!] matplotlib not installed – skipping chart.")
        return

    labels    = list(all_results.keys())
    n_groups  = len(WORKER_COUNTS)
    n_targets = len(labels)

    fig, ax = plt.subplots(figsize=(14, 7))
    bar_w   = 0.14
    index   = np.arange(n_targets)
    colors  = ['#2196F3', '#4CAF50', '#FF9800', '#E91E63', '#9C27B0']

    for i, w in enumerate(WORKER_COUNTS):
        vals = [all_results[lb][w]['throughput'] for lb in labels]
        bars = ax.bar(index + i * bar_w, vals, bar_w,
                      label=f'{w} worker{"s" if w > 1 else " "}',
                      color=colors[i], alpha=0.88, edgecolor='white',
                      linewidth=0.5)
        for bar, v in zip(bars, vals):
            if v > 0:
                ax.text(bar.get_x() + bar.get_width() / 2,
                        bar.get_height() * 1.01,
                        f'{v:,.0f}', ha='center', va='bottom',
                        fontsize=7, rotation=45)

    ax.set_xlabel('Target File', fontsize=12, labelpad=8)
    ax.set_ylabel('Throughput  (passwords / sec)', fontsize=12, labelpad=8)
    ax.set_title('CSL-G17 · Multi-Worker Password Recovery Benchmark',
                 fontsize=14, fontweight='bold', pad=12)
    ax.set_xticks(index + bar_w * (n_groups - 1) / 2)
    ax.set_xticklabels(labels, fontsize=9)
    ax.legend(fontsize=9, loc='upper left')
    ax.grid(axis='y', alpha=0.25, linestyle='--')
    ax.set_axisbelow(True)

    plt.tight_layout()
    plt.savefig(path, dpi=150)
    plt.close()
    print(f"\n  [+] Chart saved → {path}")


# ═══════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════

def main():
    print()
    print("═" * 62)
    print("  CSL-G17 · Benchmark Suite")
    print("═" * 62)

    ensure_targets()

    wordlist_path = os.path.join(TARGET_DIR, 'wordlist.txt')

    # Pre-load all files into memory
    pin_data  = load_file('own_pin.zip')
    dict_data = load_file('own_dict.zip')
    rc4_data  = load_file('own_rc4.pdf')
    aes_data  = load_file('own_aes.pdf')

    benchmarks = [
        ('own_pin.zip  (Brute 4-dig)',
         pin_data, 'zip',
         lambda: list(brute_candidates(CHARSETS['digits'], 4, 4))),

        ('own_dict.zip (Dict)',
         dict_data, 'zip',
         lambda: list(load_wordlist(wordlist_path))),

        ('own_rc4.pdf  (RC4 Dict)',
         rc4_data, 'pdf',
         lambda: list(load_wordlist(wordlist_path))),

        ('own_aes.pdf  (AES Dict)',
         aes_data, 'pdf',
         lambda: list(load_wordlist(wordlist_path))),
    ]

    all_results: dict[str, dict] = {}

    for label, data, ftype, cand_fn in benchmarks:
        print(f"\n  ── {label} " + "─" * (50 - len(label)))
        all_results[label] = benchmark_target(
            label, data, ftype, cand_fn, WORKER_COUNTS,
        )

    print_summary_table(all_results)

    chart_path = os.path.join(PROJECT_DIR, 'benchmark_chart.png')
    save_chart(all_results, chart_path)

    print()
    print("═" * 62)
    print("  Benchmark suite complete ✓")
    print("═" * 62)
    print()


if __name__ == '__main__':
    main()
