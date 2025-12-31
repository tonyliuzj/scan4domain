#!/usr/bin/env python3
"""
Keep ONLY unregistered domains in a chosen .txt file (streaming rewrite, resume-safe, multi-worker).

STRICT rule:
A domain is UNREGISTERED only if it passes ALL 3 checks:
  1) DNS A/AAAA shows NO records (or NXDOMAIN) AND no DNS hard-error
  2) DNS NS shows NO records (or NXDOMAIN) AND no DNS hard-error
  3) WHOIS does NOT indicate registered on ANY server we query (sequential)

If ANY check indicates REGISTERED -> REGISTERED -> REMOVE.
If checks are inconclusive (timeouts/errors/uncertain whois):
  - default KEEP (so you don't lose possibly-unregistered)
  - optional --remove-uncertain to remove uncertain too

WHOIS servers used (fixed list):
- whois.verisign-grs.com:43
- whois.porkbun.com:43
- whois.godaddy.com:43
- whois.internic.net:43

Ctrl+C fix (no freeze / no long wait):
- Uses a custom daemon-thread executor whose shutdown never blocks.
- On Ctrl+C we:
    * commit whatever results are already in-order
    * write already-read-but-not-committed lines unchanged
    * copy remainder unchanged
  Then exit immediately without waiting for in-flight DNS/WHOIS workers.

Console output behavior (as requested):
- Console output does NOT preserve file order.
- It prints as soon as a worker finishes (completion order).
- File output still preserves original order (for correctness + resume-safe rewrite).

Dependencies:
  python3 -m pip install dnspython
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import os
import random
import re
import shutil
import socket
import sys
import threading
import time
import queue
from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List

import dns.exception
import dns.rcode
import dns.resolver

# User rejects IDN: ASCII-only domains (no punycode).
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

WHOIS_SERVERS = [
    ("whois.verisign-grs.com", 43),
    ("whois.porkbun.com", 43),
    ("whois.godaddy.com", 43),
    ("whois.internic.net", 43),
]

# Heuristics for WHOIS parsing
RE_NO_MATCH = re.compile(
    r"(no match|not found|no data found|no entries found|domain not found|"
    r"status:\s*free|the domain has not been registered|available)",
    re.IGNORECASE,
)
RE_REGISTERED = re.compile(
    r"(domain name:\s*|registry domain id:\s*|registrar:\s*|"
    r"creation date:\s*|registered on:\s*|updated date:\s*)",
    re.IGNORECASE,
)

# Global stop flag: set on Ctrl+C to encourage workers to bail early (best effort).
stop_event = threading.Event()


@dataclass
class DNSResult:
    status: str  # has / nxdomain / no / timeout / servfail / refused / other_error
    reason: str


@dataclass
class DomainDecision:
    dom: str
    keep: bool
    classification: str  # unregistered / registered / uncertain
    method: str          # DNS / WHOIS / WORKER
    reason: str


class StopNow(Exception):
    """Internal control flow used to safely abort on Ctrl+C and finalize."""


class DaemonExecutor:
    """
    Small executor that returns concurrent.futures.Future objects but uses daemon worker threads.

    Properties:
      - worker threads are daemon => program can exit immediately after Ctrl+C finalization
      - shutdown(wait=False) never blocks
      - compatible with concurrent.futures.wait() and Future API
    """

    def __init__(self, max_workers: int, thread_name_prefix: str = "worker"):
        if max_workers < 1:
            raise ValueError("max_workers must be >= 1")
        self._max_workers = max_workers
        self._name_prefix = thread_name_prefix
        self._q: queue.Queue[object] = queue.Queue()
        self._threads: list[threading.Thread] = []
        self._lock = threading.Lock()
        self._shutdown = False
        self._started = False

    def _start_threads(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            for i in range(self._max_workers):
                t = threading.Thread(
                    target=self._worker_loop,
                    name=f"{self._name_prefix}_{i}",
                    daemon=True,
                )
                t.start()
                self._threads.append(t)

    def submit(self, fn, /, *args, **kwargs) -> cf.Future:
        with self._lock:
            if self._shutdown:
                raise RuntimeError("cannot schedule new futures after shutdown")
        self._start_threads()
        fut: cf.Future = cf.Future()
        self._q.put((fut, fn, args, kwargs))
        return fut

    def _worker_loop(self) -> None:
        while True:
            item = self._q.get()
            if item is None:
                return

            fut, fn, args, kwargs = item  # type: ignore[misc]
            if not fut.set_running_or_notify_cancel():
                continue

            try:
                if stop_event.is_set():
                    raise RuntimeError("stop requested")
                res = fn(*args, **kwargs)
            except BaseException as e:
                try:
                    fut.set_exception(e)
                except BaseException:
                    pass
            else:
                try:
                    fut.set_result(res)
                except BaseException:
                    pass

    def shutdown(self, wait: bool = False, cancel_futures: bool = False) -> None:
        with self._lock:
            self._shutdown = True

        if cancel_futures:
            # Best-effort: drain queued tasks and cancel them (running tasks cannot be cancelled).
            while True:
                try:
                    item = self._q.get_nowait()
                except queue.Empty:
                    break
                if item is None:
                    self._q.put(None)
                    break
                fut, _, _, _ = item  # type: ignore[misc]
                try:
                    fut.cancel()
                except BaseException:
                    pass

        # Tell workers to exit.
        for _ in self._threads:
            self._q.put(None)

        if wait:
            for t in self._threads:
                try:
                    t.join()
                except BaseException:
                    pass


def normalize_domain(s: str) -> str:
    s = s.strip().lower()
    s = re.sub(r"^https?://", "", s)
    s = s.split("/")[0].split("?")[0].split("#")[0]
    return s.rstrip(".")


def list_txt_files(directory: str) -> list[str]:
    out: list[str] = []
    for name in os.listdir(directory):
        p = os.path.join(directory, name)
        if os.path.isfile(p) and name.lower().endswith(".txt"):
            out.append(name)
    return sorted(out, key=str.lower)


def choose_file_interactive(directory: str) -> str:
    files = list_txt_files(directory)
    if not files:
        print(f"No .txt files found in: {directory}", file=sys.stderr)
        raise SystemExit(2)

    print("\nSelect a .txt file to process:\n")
    for i, name in enumerate(files, start=1):
        print(f"  {i:2d}) {name}")
    print("   0) Cancel\n")

    while True:
        choice = input("Enter number: ").strip()
        if choice == "0":
            raise SystemExit(0)
        try:
            idx = int(choice)
            if 1 <= idx <= len(files):
                return os.path.join(directory, files[idx - 1])
        except ValueError:
            pass
        print("Invalid selection. Try again.")


def prompt_workers(default_workers: int = 20) -> int:
    while True:
        s = input(f"Number of workers/threads [{default_workers}]: ").strip()
        if s == "":
            return max(1, default_workers)
        try:
            n = int(s)
            if n >= 1:
                return n
        except ValueError:
            pass
        print("Please enter an integer >= 1.")


def is_domain_line(raw: str) -> tuple[bool, Optional[str]]:
    stripped = raw.strip()
    if stripped == "" or stripped.startswith("#"):
        return False, None
    token = stripped.split()[0]
    dom = normalize_domain(token)
    return (True, dom) if DOMAIN_RE.match(dom) else (False, None)


def count_domains(path: str) -> int:
    total = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ok, _ = is_domain_line(line)
            if ok:
                total += 1
    return total


def render_bar(done: int, total: int, width: int = 18) -> str:
    if total <= 0:
        return "[" + ("#" * width) + "]"
    frac = min(max(done / total, 0.0), 1.0)
    filled = int(frac * width)
    return "[" + ("#" * filled) + ("-" * (width - filled)) + "]"


# Thread-local resolver
_tls = threading.local()


def _get_thread_resolver(dns_timeout: float, dns_lifetime: float) -> dns.resolver.Resolver:
    r = getattr(_tls, "resolver", None)
    if r is None:
        r = dns.resolver.Resolver(configure=True)
        r.timeout = float(dns_timeout)
        r.lifetime = float(dns_lifetime)
        # Best effort: disable search suffix expansion
        try:
            r.use_search_by_default = False
            r.search = []
        except Exception:
            pass
        _tls.resolver = r
    return r


def dns_has_record(domain: str, rtype: str, resolver: dns.resolver.Resolver) -> DNSResult:
    qname = domain.rstrip(".") + "."
    try:
        # dnspython compatibility: some versions don't support search= kwarg.
        try:
            ans = resolver.resolve(qname, rtype, raise_on_no_answer=False, search=False)
        except TypeError:
            ans = resolver.resolve(qname, rtype, raise_on_no_answer=False)

        if hasattr(ans, "response") and ans.response and ans.response.rcode() == dns.rcode.NXDOMAIN:
            return DNSResult("nxdomain", f"DNS NXDOMAIN for {rtype}")

        if ans.rrset is not None and len(ans.rrset) > 0:
            return DNSResult("has", f"DNS {rtype} ({len(ans.rrset)} records)")

        return DNSResult("no", f"DNS NOERROR but no {rtype}")

    except dns.resolver.NXDOMAIN:
        return DNSResult("nxdomain", f"DNS NXDOMAIN for {rtype}")
    except dns.resolver.Timeout:
        return DNSResult("timeout", f"DNS timeout for {rtype}")
    except dns.resolver.NoNameservers:
        return DNSResult("servfail", f"DNS no nameservers / SERVFAIL-like for {rtype}")
    except dns.resolver.NoAnswer:
        return DNSResult("no", f"DNS no answer for {rtype}")
    except dns.exception.DNSException as e:
        msg = str(e).lower()
        if "refused" in msg:
            return DNSResult("refused", f"DNS refused for {rtype}: {e}")
        return DNSResult("other_error", f"DNS error for {rtype}: {e}")


def whois_query(host: str, port: int, q: str, timeout: float) -> str:
    """
    Interrupt-aware WHOIS query:
    - overall deadline (timeout)
    - small recv timeouts so stop_event can be observed quickly
    - short connect timeout so Ctrl+C doesn't feel stuck in connect()
    """
    deadline = time.monotonic() + float(timeout)
    data_parts: List[bytes] = []

    connect_timeout = min(1.0, float(timeout))
    with socket.create_connection((host, port), timeout=connect_timeout) as sock:
        sock.sendall((q + "\r\n").encode("utf-8", errors="ignore"))

        while True:
            if stop_event.is_set():
                break

            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise socket.timeout("WHOIS overall timeout")

            sock.settimeout(min(0.5, remaining))
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue

            if not chunk:
                break
            data_parts.append(chunk)

    return b"".join(data_parts).decode("utf-8", errors="replace")


def classify_whois_text(text: str) -> Optional[bool]:
    """
    True  => registered
    False => unregistered
    None  => uncertain
    """
    if not text or len(text.strip()) < 10:
        return None
    if RE_NO_MATCH.search(text):
        return False
    if RE_REGISTERED.search(text):
        return True
    return None


def whois_sequential(domain: str, *, timeout: float) -> Tuple[Optional[bool], str]:
    """
    Query servers sequentially (random order):
    - If ANY server says registered => True immediately.
    - Else if at least one server says unregistered => False.
    - Else => None.
    """
    servers = WHOIS_SERVERS[:]
    random.shuffle(servers)

    saw_unregistered = False
    reasons: List[str] = []

    for host, port in servers:
        if stop_event.is_set():
            return None, "WHOIS skipped (stop requested)"

        try:
            txt = whois_query(host, port, domain, timeout=timeout)
            res = classify_whois_text(txt)
            if res is True:
                reasons.append(f"{host}: reg")
                return True, "WHOIS registered (short-circuit) [" + ", ".join(reasons) + "]"
            if res is False:
                saw_unregistered = True
                reasons.append(f"{host}: free")
            else:
                reasons.append(f"{host}: uncertain")
        except Exception as e:
            reasons.append(f"{host}: error ({e})")

    if saw_unregistered:
        return False, "WHOIS unregistered (none said registered) [" + ", ".join(reasons) + "]"
    return None, "WHOIS uncertain (no clear result) [" + ", ".join(reasons) + "]"


def check_one_domain(
    dom: str,
    *,
    dns_timeout: float,
    dns_lifetime: float,
    remove_uncertain: bool,
    whois_timeout: float,
) -> DomainDecision:
    if stop_event.is_set():
        return DomainDecision(dom, keep=True, classification="uncertain", method="WORKER", reason="stop requested")

    resolver = _get_thread_resolver(dns_timeout, dns_lifetime)

    # ---- Check 1: A / AAAA ----
    a = dns_has_record(dom, "A", resolver)
    if a.status == "has":
        return DomainDecision(dom, keep=False, classification="registered", method="DNS", reason=a.reason)

    aaaa = dns_has_record(dom, "AAAA", resolver)
    if aaaa.status == "has":
        return DomainDecision(dom, keep=False, classification="registered", method="DNS", reason=aaaa.reason)

    # A/AAAA passes only if both are (no or nxdomain) AND neither is a hard error
    a_ok = a.status in ("no", "nxdomain")
    aaaa_ok = aaaa.status in ("no", "nxdomain")
    a_err = not a_ok
    aaaa_err = not aaaa_ok

    # ---- Check 2: NS ----
    ns = dns_has_record(dom, "NS", resolver)
    if ns.status == "has":
        return DomainDecision(dom, keep=False, classification="registered", method="DNS", reason=ns.reason)

    ns_ok = ns.status in ("no", "nxdomain")
    ns_err = not ns_ok

    # ---- Check 3: WHOIS ----
    whois_res, whois_reason = whois_sequential(dom, timeout=whois_timeout)
    if whois_res is True:
        return DomainDecision(dom, keep=False, classification="registered", method="WHOIS", reason=whois_reason)

    whois_ok = whois_res is False
    whois_uncertain = whois_res is None

    # ---- Final strict rule: UNREGISTERED only if ALL THREE checks pass ----
    if a_ok and aaaa_ok and ns_ok and whois_ok and not (a_err or aaaa_err or ns_err):
        return DomainDecision(
            dom,
            keep=True,
            classification="unregistered",
            method="WHOIS",
            reason="Passed all checks: A/AAAA none, NS none, WHOIS not registered. " + whois_reason,
        )

    keep = not remove_uncertain
    reasons: List[str] = []
    if a_err or aaaa_err:
        reasons.append(f"A/AAAA DNS error (A={a.status}, AAAA={aaaa.status})")
    if ns_err:
        reasons.append(f"NS DNS error (NS={ns.status})")
    if whois_uncertain:
        reasons.append("WHOIS uncertain")
    if not reasons:
        reasons.append("Did not strictly pass WHOIS unregistered")

    return DomainDecision(
        dom,
        keep=keep,
        classification="uncertain",
        method="WHOIS",
        reason="; ".join(reasons) + " | " + whois_reason,
    )


def decision_label(dec: DomainDecision) -> str:
    if dec.classification == "unregistered":
        return "UNREGISTERED (KEPT)"
    if dec.classification == "registered":
        return "REGISTERED (REMOVED)"
    return "UNCERTAIN (REMOVED)" if not dec.keep else "UNCERTAIN (KEPT)"


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Keep only unregistered domains; remove registered domains (strict: must pass A/AAAA, NS, WHOIS). Resume-safe + multi-worker."
    )
    ap.add_argument("--dir", default=".", help="Directory to scan for .txt files (default: current directory)")
    ap.add_argument("--dns-timeout", type=float, default=2.5, help="DNS timeout seconds")
    ap.add_argument("--dns-lifetime", type=float, default=4.0, help="DNS lifetime seconds (total)")
    ap.add_argument("--whois-timeout", type=float, default=8.0, help="WHOIS socket timeout seconds (overall per server)")
    ap.add_argument("--dry-run", action="store_true", help="Do not modify the file (still checks + prints results)")
    ap.add_argument("--flush-every", type=int, default=50, help="Flush temp output every N committed writes (default: 50)")
    ap.add_argument("--remove-uncertain", action="store_true", help="Also remove UNCERTAIN domains (default keeps them)")
    ap.add_argument("--workers", type=int, default=0, help="Number of worker threads (0 => ask interactively)")
    ap.add_argument(
        "--max-pending",
        type=int,
        default=0,
        help="Max in-flight domain checks (0 => auto). Higher buffers more out-of-order completions.",
    )
    args = ap.parse_args()

    directory = os.path.abspath(args.dir)
    path = choose_file_interactive(directory)

    workers = args.workers if args.workers and args.workers > 0 else prompt_workers(default_workers=20)

    # Default higher buffer reduces stalls behind slow domains (more RAM, more throughput).
    max_pending = args.max_pending if args.max_pending and args.max_pending > 0 else max(500, workers * 250)

    total_to_check = count_domains(path)
    if total_to_check == 0:
        print(f"\nNo valid domain lines found in: {os.path.basename(path)}")
        return 0

    tmp_path = path + ".tmp"
    backup_path = path + ".bak"

    if not args.dry_run:
        shutil.copy2(path, backup_path)

    # Committed counters (for final summary; file must be written in-order)
    committed_checked = 0
    kept_unregistered = 0
    removed_registered = 0
    committed_uncertain = 0

    # Completed counter (for console progress; completion-order)
    completed_checks = 0

    interrupted = False

    # Ordered-commit state
    next_write = 0
    results_map: Dict[int, Tuple[str, Optional[DomainDecision]]] = {}  # idx -> ("passthrough"/"domain", decision)
    future_to_meta: Dict[cf.Future, Tuple[int, str]] = {}              # future -> (idx, dom)

    # Store already-read lines until committed (so Ctrl+C can write them back unchanged)
    read_raw: Dict[int, str] = {}  # idx -> raw line

    out_f = None
    in_f = None
    line_idx = 0  # next index to assign

    def commit_ready():
        nonlocal next_write, committed_checked, kept_unregistered, removed_registered, committed_uncertain

        while next_write in results_map:
            kind, decision = results_map.pop(next_write)
            raw = read_raw.pop(next_write, "")

            if kind == "passthrough":
                if out_f is not None:
                    out_f.write(raw)
            else:
                assert decision is not None
                committed_checked += 1

                if decision.classification == "unregistered":
                    kept_unregistered += 1
                elif decision.classification == "registered":
                    removed_registered += 1
                else:
                    committed_uncertain += 1

                if decision.keep and out_f is not None:
                    out_f.write(raw)

                if out_f is not None and (committed_checked % max(1, args.flush_every) == 0):
                    out_f.flush()

            next_write += 1

    def finalize_uncommitted_and_remainder():
        """Write back already-read-but-not-committed lines unchanged, then copy remainder unchanged."""
        if out_f is None:
            return

        for idx in range(next_write, line_idx):
            out_f.write(read_raw.get(idx, ""))

        if in_f is not None:
            shutil.copyfileobj(in_f, out_f)

    def harvest_done(timeout: float) -> None:
        """Collect finished futures into results_map; PRINT on completion (unordered)."""
        nonlocal completed_checks
        if not future_to_meta:
            return

        done, _ = cf.wait(list(future_to_meta.keys()), timeout=timeout, return_when=cf.FIRST_COMPLETED)
        for fut in done:
            idx, dom = future_to_meta.pop(fut)
            try:
                dec = fut.result()
            except KeyboardInterrupt:
                raise StopNow()
            except Exception as e:
                # Default KEEP on worker failure -> uncertain
                dec = DomainDecision(dom=dom, keep=True, classification="uncertain", method="WORKER", reason=f"worker error: {e}")

            completed_checks += 1
            results_map[idx] = ("domain", dec)

            # Console output: completion order (NOT file order)
            bar = render_bar(completed_checks, total_to_check, width=18)
            print(
                f"{bar} completed {completed_checks:,}/{total_to_check:,}  "
                f"(idx {idx}) {dec.dom} -> {decision_label(dec)}  [{dec.method}: {dec.reason}]",
                flush=True,
            )

    ex: Optional[DaemonExecutor] = None
    try:
        out_f = open(tmp_path, "w", encoding="utf-8", newline="\n") if not args.dry_run else None
        in_f = open(path, "r", encoding="utf-8", errors="replace")

        ex = DaemonExecutor(max_workers=workers, thread_name_prefix="domchk")

        try:
            while True:
                # Backpressure: if too many in-flight tasks, keep harvesting.
                while len(future_to_meta) >= max_pending:
                    try:
                        harvest_done(timeout=0.25)
                    except KeyboardInterrupt:
                        raise StopNow()
                    commit_ready()
                    if len(future_to_meta) >= max_pending:
                        time.sleep(0.02)

                # Read next line
                try:
                    raw = in_f.readline()
                except KeyboardInterrupt:
                    raise StopNow()

                if raw == "":
                    break  # EOF

                idx = line_idx
                line_idx += 1
                read_raw[idx] = raw

                ok, dom = is_domain_line(raw)
                if not ok:
                    results_map[idx] = ("passthrough", None)
                else:
                    fut = ex.submit(
                        check_one_domain,
                        dom,
                        dns_timeout=args.dns_timeout,
                        dns_lifetime=args.dns_lifetime,
                        remove_uncertain=args.remove_uncertain,
                        whois_timeout=args.whois_timeout,
                    )
                    future_to_meta[fut] = (idx, dom)

                # Opportunistically harvest quick completions; commit in-order
                try:
                    harvest_done(timeout=0.0)
                except KeyboardInterrupt:
                    raise StopNow()
                commit_ready()

            # EOF: drain futures (prints as each completes)
            while future_to_meta:
                try:
                    harvest_done(timeout=0.25)
                except KeyboardInterrupt:
                    raise StopNow()
                commit_ready()

        except StopNow:
            interrupted = True
            stop_event.set()
            print("\nCtrl+C received — saving committed progress; keeping unread/uncommitted lines unchanged so you can resume next run...")

            # Cancel not-done futures (best-effort)
            for fut in list(future_to_meta.keys()):
                if not fut.done():
                    fut.cancel()

            # Harvest any already-finished futures (non-blocking) so they print + can be committed if in-order
            try:
                harvest_done(timeout=0.0)
            except Exception:
                pass
            commit_ready()

            # Write back everything else unchanged + copy remainder
            finalize_uncommitted_and_remainder()

    finally:
        if in_f is not None:
            try:
                in_f.close()
            except Exception:
                pass
        if out_f is not None:
            try:
                out_f.flush()
                out_f.close()
            except Exception:
                pass

        # Never block shutdown; daemon threads mean we can exit immediately.
        if ex is not None:
            try:
                ex.shutdown(wait=False, cancel_futures=True)
            except Exception:
                pass

    if args.dry_run:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        print("\nDry run: no changes written.")
        return 0

    # Always apply partial/full results (resume-safe)
    try:
        os.replace(tmp_path, path)
    except Exception as e:
        print(f"Failed to replace original file: {e}", file=sys.stderr)
        print(f"Backup is still at: {backup_path}", file=sys.stderr)
        print(f"Temp output is at: {tmp_path}", file=sys.stderr)
        return 2

    print("\n=== Summary ===")
    print(f"Workers: {workers} (max pending: {max_pending})")
    print(f"File updated: {os.path.basename(path)}")
    print(f"Backup saved: {os.path.basename(backup_path)}")
    print(f"Completed checks: {completed_checks:,}/{total_to_check:,} (printed in completion order)")
    print(f"Committed (written): {committed_checked:,}/{total_to_check:,} (file order)")
    print(f"Kept unregistered: {kept_unregistered:,}")
    print(f"Removed registered: {removed_registered:,}")
    print(f"Uncertain: {committed_uncertain:,} ({'removed' if args.remove_uncertain else 'kept'})")

    return 130 if interrupted else 0


if __name__ == "__main__":
    raise SystemExit(main())
