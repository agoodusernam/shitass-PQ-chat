"""
Speed / Performance benchmark for SecureChatProtocol encryption & decryption.

Measures:
  - Total messages
  - Total plaintext bytes
  - Total padded bytes (next 512 bytes as per protocol padding rule)
  - Total encrypted bytes (length of serialized encrypted messages)
  - Total encryption time / decryption time
  - Messages per second (enc, dec, end-to-end)
  - Throughput (plaintext bytes / sec) for encryption, decryption, combined
  - Latency statistics (min / max / avg / median / p95 / p99) for enc & dec
  - Size bucket statistics (≤64, ≤256, ≤1024, ≤4096, >4096) – messages & throughput

Usage (Windows cmd.exe examples):
  python speed_test.py
  python speed_test.py -n 5000 --min 32 --max 2048 --mode random
  python speed_test.py -n 2000 --fixed 1024 --mode fixed
  python speed_test.py -n 1000 --sizes 16,32,64,128,256

Notes:
  - Padding: The protocol pads to the next 512 bytes boundary (adding an extra 512 even if already aligned). We compute padded size analytically; we don't introspect internals.
  - Encrypted size: Actual length of the returned JSON bytes of encrypt_message().
  - All timings use perf_counter_ns for high resolution.
  - Warmup iterations are excluded from statistics to allow JIT-like warm cache effects to stabilize.
  - No external dependencies required beyond those already in requirements.txt.
"""
from __future__ import annotations

import argparse
import random
import statistics
import string
import sys
import time
from dataclasses import dataclass
from typing import Sequence, Any
import json
import os
from datetime import datetime

from shared import SecureChatProtocol


# ---------------------------------- Data Structures ---------------------------------- #

@dataclass
class TimingStats:
    samples_ns: list[int]
    
    def count(self) -> int:
        return len(self.samples_ns)
    
    def total_ns(self) -> int:
        return sum(self.samples_ns)
    
    def min_ns(self) -> int:
        return min(self.samples_ns) if self.samples_ns else 0
    
    def max_ns(self) -> int:
        return max(self.samples_ns) if self.samples_ns else 0
    
    def avg_ns(self) -> float:
        return self.total_ns() / self.count() if self.samples_ns else 0.0
    
    def median_ns(self) -> float:
        if not self.samples_ns:
            return 0.0
        return statistics.median(self.samples_ns)
    
    def percentile_ns(self, pct: float) -> float:
        if not self.samples_ns:
            return 0.0
        if pct <= 0:
            return float(self.min_ns())
        if pct >= 100:
            return float(self.max_ns())
        # Manual percentile (nearest-rank) to avoid numpy
        ordered = sorted(self.samples_ns)
        k = (len(ordered) - 1) * (pct / 100.0)
        f = int(k)
        c = min(f + 1, len(ordered) - 1)
        if f == c:
            return float(ordered[f])
        d0 = ordered[f] * (c - k)
        d1 = ordered[c] * (k - f)
        return float(d0 + d1)
    
    def as_dict(self) -> dict[str, float]:
        return {
            "count":     self.count(),
            "total_ms":  self.total_ns() / 1e6,
            "min_us":    self.min_ns() / 1e3,
            "max_us":    self.max_ns() / 1e3,
            "avg_us":    self.avg_ns() / 1e3,
            "median_us": self.median_ns() / 1e3,
            "p95_us":    self.percentile_ns(95) / 1e3,
            "p99_us":    self.percentile_ns(99) / 1e3,
        }


# ---------------------------------- Utility Functions ---------------------------------- #

PRINTABLE = string.ascii_letters + string.digits + string.punctuation + " "


def make_message(length: int) -> str:
    # Random printable; ensure no embedded null (not required, but fine)
    return ''.join(random.choice(PRINTABLE) for _ in range(length))


def padded_size(length: int) -> int:
    kib = 512
    current_kib = (length + kib - 1) // kib
    target_size = current_kib * kib
    if target_size == length:
        target_size += kib
    return target_size


SIZE_BUCKETS = [64, 256, 1024, 4096]


def bucket_for(size: int) -> str:
    for b in SIZE_BUCKETS:
        if size <= b:
            return f"<={b}"
    return ">4096"


# ---------------------------------- Benchmark Core ---------------------------------- #

def run_benchmark(num_messages: int, size_mode: str, min_size: int, max_size: int, fixed_size: int,
                  explicit_sizes: Sequence[int] | None, warmup: int, seed: int | None) -> dict[str, Any]:
    if seed is not None:
        random.seed(seed)
    
    # Initialize protocols & perform key exchange
    proto_a = SecureChatProtocol()
    proto_b = SecureChatProtocol()
    pub_a, priv_a = proto_a.generate_keypair()
    init_msg = proto_a.create_key_exchange_init(pub_a)
    shared_secret_b, ciphertext, _ = proto_b.process_key_exchange_init(init_msg)
    resp_msg = proto_b.create_key_exchange_response(ciphertext)
    shared_secret_a, _ = proto_a.process_key_exchange_response(resp_msg, priv_a)
    
    assert shared_secret_a == shared_secret_b, "Shared secrets mismatch during setup"
    
    # Prepare size sequence
    sizes: list[int] = []
    if size_mode == "fixed":
        sizes = [fixed_size] * num_messages
    elif size_mode == "random":
        if min_size > max_size:
            raise ValueError("min_size cannot be greater than max_size")
        sizes = [random.randint(min_size, max_size) for _ in range(num_messages)]
    elif size_mode == "list":
        if not explicit_sizes:
            raise ValueError("--sizes required for list mode")
        # Repeat / truncate to match num_messages
        rep = (num_messages + len(explicit_sizes) - 1) // len(explicit_sizes)
        sizes = (list(explicit_sizes) * rep)[:num_messages]
    else:
        raise ValueError(f"Unknown size_mode {size_mode}")
    
    # Warmup (not measured)
    for _ in range(warmup):
        m = make_message(32)
        enc = proto_a.encrypt_message(m)
        dec = proto_b.decrypt_message(enc)
        if dec != m:
            raise RuntimeError("Warmup decryption mismatch")
    
    enc_times: list[int] = []
    dec_times: list[int] = []
    
    total_plaintext_bytes = 0
    total_padded_bytes = 0
    total_encrypted_bytes = 0
    
    bucket_counts: dict[str, int] = {bucket_for(0): 0}
    # ensure all buckets exist
    for b in SIZE_BUCKETS:
        bucket_counts[f"<={b}"] = 0
    bucket_counts[">4096"] = 0
    
    bucket_plain_bytes: dict[str, int] = {k: 0 for k in bucket_counts}
    bucket_enc_bytes: dict[str, int] = {k: 0 for k in bucket_counts}
    
    start_wall = time.perf_counter_ns()
    for sz in sizes:
        bucket = bucket_for(sz)
        bucket_counts[bucket] += 1
        msg = make_message(sz)
        
        # Encrypt timing
        t0 = time.perf_counter_ns()
        encrypted = proto_a.encrypt_message(msg)
        t1 = time.perf_counter_ns()
        enc_times.append(t1 - t0)
        
        # Decrypt timing
        t2 = time.perf_counter_ns()
        decrypted = proto_b.decrypt_message(encrypted)
        t3 = time.perf_counter_ns()
        dec_times.append(t3 - t2)
        
        if decrypted != msg:
            raise RuntimeError("Decryption mismatch")
        
        # Accounting
        total_plaintext_bytes += sz
        total_padded_bytes += padded_size(sz)
        enc_len = len(encrypted)
        total_encrypted_bytes += enc_len
        bucket_plain_bytes[bucket] += sz
        bucket_enc_bytes[bucket] += enc_len
    end_wall = time.perf_counter_ns()
    
    wall_ns = end_wall - start_wall
    
    enc_stats = TimingStats(enc_times)
    dec_stats = TimingStats(dec_times)
    
    # Throughput calculations use plaintext bytes as the meaningful payload.
    enc_total_s = enc_stats.total_ns() / 1e9 if enc_stats.count() else 0.0
    dec_total_s = dec_stats.total_ns() / 1e9 if dec_stats.count() else 0.0
    wall_s = wall_ns / 1e9 if wall_ns else 0.0
    
    results = {
        "config":    {
            "num_messages": num_messages,
            "size_mode":    size_mode,
            "min_size":     min_size,
            "max_size":     max_size,
            "fixed_size":   fixed_size,
            "warmup":       warmup,
            "seed":         seed,
        },
        "aggregate": {
            "messages":                       num_messages,
            "total_plaintext_bytes":          total_plaintext_bytes,
            "total_padded_bytes":             total_padded_bytes,
            "total_encrypted_bytes":          total_encrypted_bytes,
            "encryption_time_s":              enc_total_s,
            "decryption_time_s":              dec_total_s,
            "wall_clock_time_s":              wall_s,
            "enc_msgs_per_sec":               num_messages / enc_total_s if enc_total_s else 0.0,
            "dec_msgs_per_sec":               num_messages / dec_total_s if dec_total_s else 0.0,
            "end_to_end_msgs_per_sec":        num_messages / wall_s if wall_s else 0.0,
            "enc_throughput_plain_MBps":      (total_plaintext_bytes / (
                        1024 * 1024)) / enc_total_s if enc_total_s else 0.0,
            "dec_throughput_plain_MBps":      (total_plaintext_bytes / (
                        1024 * 1024)) / dec_total_s if dec_total_s else 0.0,
            "combined_throughput_plain_MBps": (total_plaintext_bytes / (1024 * 1024)) / wall_s if wall_s else 0.0,
            "enc_throughput_encrypted_MBps":  (total_encrypted_bytes / (
                        1024 * 1024)) / enc_total_s if enc_total_s else 0.0,
            "dec_throughput_encrypted_MBps":  (total_encrypted_bytes / (
                        1024 * 1024)) / dec_total_s if dec_total_s else 0.0,
        },
        "latency":   {
            "encryption": enc_stats.as_dict(),
            "decryption": dec_stats.as_dict(),
        },
        "buckets":   {
            b: {
                "messages":        bucket_counts[b],
                "plaintext_bytes": bucket_plain_bytes[b],
                "encrypted_bytes": bucket_enc_bytes[b],
            } for b in sorted(bucket_counts.keys(), key=lambda x: (len(x), x))
        }
    }
    
    return results


# ---------------------------------- Reporting ---------------------------------- #

RESULTS_FILE = "speed_test_last.json"

def load_previous_results(path: str) -> dict[str, Any] | None:
    try:
        if not os.path.exists(path):
            return None
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        # If file is corrupt or unreadable, ignore silently for benchmark continuity
        return None


def save_results(path: str, results: dict[str, Any]) -> None:
    payload = dict(results)
    payload["timestamp"] = datetime.now().isoformat(timespec='seconds')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(payload, f, indent=4, default=str)


def compute_deltas(prev: dict[str, Any], curr: dict[str, Any]) -> dict[str, dict[str, float]]:
    keys = [
        "encryption_time_s",
        "decryption_time_s",
        "wall_clock_time_s",
        "enc_msgs_per_sec",
        "dec_msgs_per_sec",
        "end_to_end_msgs_per_sec",
        "enc_throughput_plain_MBps",
        "dec_throughput_plain_MBps",
        "combined_throughput_plain_MBps",
    ]
    out: dict[str, dict[str, float]] = {}
    p_agg = prev.get("aggregate", {}) if prev else {}
    c_agg = curr.get("aggregate", {})
    for k in keys:
        pv = float(p_agg.get(k, 0.0)) if p_agg else None
        cv = float(c_agg.get(k, 0.0))
        if pv is None:
            continue
        delta = cv - pv
        pct = (delta / pv * 100.0) if pv not in (0, None) else float('inf')
        out[k] = {"prev": pv, "curr": cv, "delta": delta, "pct": pct}
    return out


def print_comparison(prev: dict[str, Any] | None, curr: dict[str, Any]) -> None:
    if not prev:
        print("\nNo previous results found to compare against (this might be the first run).")
        return
    print("\nChange vs previous run:")
    deltas = compute_deltas(prev, curr)
    # Friendly labels
    labels = {
        "encryption_time_s": "Encryption time (s)",
        "decryption_time_s": "Decryption time (s)",
        "wall_clock_time_s": "Wall clock time (s)",
        "enc_msgs_per_sec": "Enc msgs/sec",
        "dec_msgs_per_sec": "Dec msgs/sec",
        "end_to_end_msgs_per_sec": "End-to-end msgs/sec",
        "enc_throughput_plain_MBps": "Enc throughput (MB/s)",
        "dec_throughput_plain_MBps": "Dec throughput (MB/s)",
        "combined_throughput_plain_MBps": "Combined throughput (MB/s)",
    }
    for k, stat in deltas.items():
        prev_v = stat["prev"]
        curr_v = stat["curr"]
        delta = stat["delta"]
        pct = stat["pct"]
        pct_str = (f"{pct:+.2f}%" if pct != float('inf') else "n/a")
        print(f"  {labels.get(k, k):28}: {curr_v:.4f} (Δ {delta:+.4f}, {pct_str} vs prev {prev_v:.4f})")

def human_bytes(n: int) -> str:
    units = ["B", "KB", "MB", "GB"]
    size = float(n)
    for u in units:
        if size < 1024 or u == units[-1]:
            return f"{size:.2f} {u}" if u != "B" else f"{int(size)} B"
        size /= 1024
    return f"{size:.2f} GB"


def print_report(results: dict[str, Any]) -> None:
    agg = results["aggregate"]
    enc_lat = results["latency"]["encryption"]
    dec_lat = results["latency"]["decryption"]
    
    print("")
    print("=== SecureChat Encryption / Decryption Benchmark ===")
    print("Configuration:")
    cfg = results["config"]
    for k, v in cfg.items():
        print(f"  {k}: {v}")
    
    print("\nAggregate:")
    print(f"  Messages:                {agg['messages']}")
    print(f"  Plaintext bytes:         {agg['total_plaintext_bytes']} ({human_bytes(agg['total_plaintext_bytes'])})")
    print(f"  Padded bytes:            {agg['total_padded_bytes']} ({human_bytes(agg['total_padded_bytes'])})")
    print(f"  Encrypted bytes:         {agg['total_encrypted_bytes']} ({human_bytes(agg['total_encrypted_bytes'])})")
    print(f"  Encryption time:         {agg['encryption_time_s']:.6f} s")
    print(f"  Decryption time:         {agg['decryption_time_s']:.6f} s")
    print(f"  Wall clock time:         {agg['wall_clock_time_s']:.6f} s")
    print(f"  Enc msgs/sec:            {agg['enc_msgs_per_sec']:.2f}")
    print(f"  Dec msgs/sec:            {agg['dec_msgs_per_sec']:.2f}")
    print(f"  End-to-end msgs/sec:     {agg['end_to_end_msgs_per_sec']:.2f}")
    print(f"  Enc throughput (plain):  {agg['enc_throughput_plain_MBps']:.2f} MB/s")
    print(f"  Dec throughput (plain):  {agg['dec_throughput_plain_MBps']:.2f} MB/s")
    print(f"  Combined throughput:     {agg['combined_throughput_plain_MBps']:.2f} MB/s")
    
    print("\nLatency (Encryption):")
    for k, v in enc_lat.items():
        print(f"  {k:>12}: {v:.3f}")
    print("Latency (Decryption):")
    for k, v in dec_lat.items():
        print(f"  {k:>12}: {v:.3f}")
    
    print("\nSize Buckets:")
    print("  Bucket    Messages   Plaintext Bytes   Encrypted Bytes")
    print("  -------   --------   ---------------   ---------------")
    for b, data in results["buckets"].items():
        if data["messages"] == 0:
            continue
        print(f"  {b:<8} {data['messages']:>8}   {data['plaintext_bytes']:>15}   {data['encrypted_bytes']:>15}")


# ---------------------------------- CLI ---------------------------------- #

def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Benchmark SecureChatProtocol encryption/decryption performance")
    parser.add_argument('-n', '--num', dest='num_messages', type=int, default=10000,
                        help='Number of messages to benchmark')
    parser.add_argument('--mode', choices=['random', 'fixed', 'list'], default='random',
                        help='Message size selection mode')
    parser.add_argument('--min', dest='min_size', type=int, default=16, help='Minimum message size (random mode)')
    parser.add_argument('--max', dest='max_size', type=int, default=8192, help='Maximum message size (random mode)')
    parser.add_argument('--fixed', dest='fixed_size', type=int, default=512, help='Fixed message size (fixed mode)')
    parser.add_argument('--sizes', dest='sizes', type=str, default='', help='Comma separated sizes (list mode)')
    parser.add_argument('--warmup', dest='warmup', type=int, default=50, help='Warmup iterations (not measured)')
    parser.add_argument('--seed', dest='seed', type=int, default=None, help='Random seed for reproducibility')
    parser.add_argument('--json', dest='json_out', action='store_true', help='Also print JSON version of results')
    parser.add_argument('--json-only', dest='json_only', action='store_true', help='Print ONLY JSON (no human report)')
    return parser.parse_args(argv)


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    explicit_sizes = [int(s) for s in args.sizes.split(',') if s.strip()] if args.sizes else None
    
    try:
        results = run_benchmark(
                num_messages=args.num_messages,
                size_mode=args.mode,
                min_size=args.min_size,
                max_size=args.max_size,
                fixed_size=args.fixed_size,
                explicit_sizes=explicit_sizes,
                warmup=args.warmup,
                seed=args.seed,
        )
    except KeyboardInterrupt:
        print("\nBenchmark interrupted by user")
        return 1
    except (ValueError, RuntimeError) as e:
        print(f"Error: {e}")
        return 2
    except Exception as e:  # unexpected fallback
        print(f"Unexpected error: {e}")
        return 3
    
    # Load previous results before printing
    prev = load_previous_results(RESULTS_FILE)

    if not args.json_only:
        print_report(results)
        print_comparison(prev, results)
    if args.json_out or args.json_only:
        print(json.dumps(results, indent=2, default=str))

    # Save current results for next run comparison
    try:
        save_results(RESULTS_FILE, results)
    except Exception as e:
        # Non-fatal: just report inability to save
        if not args.json_only:
            print(f"\nWarning: failed to save results to {RESULTS_FILE}: {e}")
    return 0


if __name__ == "__main__":
    main(sys.argv[1:])
