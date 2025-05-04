#!/usr/bin/env python3
import math
from typing import List, Set

# ───────────────────────────────────────────────────────────────────────────────
# 1. WHEEL-ROOTS AND FORMULA OF PRIMES
# ───────────────────────────────────────────────────────────────────────────────
def compute_roots() -> List[int]:
    """Compute the 48 wheel-roots r_i in [11,211] that are coprime to 210."""
    return [n for n in range(11, 212) if math.gcd(n, 210) == 1]

def compute_L(roots: List[int]) -> List[Set[int]]:
    """
    For each root r_i, compute the set L[i] of cycle-indices ℓ = 1 + (q*·r_i - q)/210
    where q and q* run over all roots giving a multiple of 210.
    """
    L: List[Set[int]] = []
    for r in roots:
        Li: Set[int] = set()
        for q in roots:
            for q_hat in roots:
                diff = q_hat * r - q
                if diff % 210 == 0:
                    ℓ = 1 + diff // 210
                    Li.add(ℓ)
                    break
        L.append(Li)
    return L

def is_prime_wheel(n: int, roots: List[int], L: List[Set[int]]) -> bool:
    """Constant–time prime test via the 210-wheel formula."""
    if n in (2, 3, 5, 7):
        return True
    if n < 11 or any(n % p == 0 for p in (2, 3, 5, 7)):
        return False
    for i, r in enumerate(roots):
        if (n - r) % 210 == 0:
            k = (n - r) // 210
            return (k + 1) not in L[i]
    return False

# ───────────────────────────────────────────────────────────────────────────────
# 2. COUNTING FUNCTIONS π(x) AND π₂(x)
# ───────────────────────────────────────────────────────────────────────────────
def pi(x: int, roots: List[int], L: List[Set[int]]) -> int:
    """Count primes ≤ x."""
    return sum(1 for n in range(2, x + 1)
               if is_prime_wheel(n, roots, L))

def pi2(x: int, roots: List[int], L: List[Set[int]]) -> int:
    """Count twin primes (n, n+2) with n+2 ≤ x."""
    return sum(1 for n in range(2, x - 1)
               if is_prime_wheel(n, roots, L)
               and is_prime_wheel(n + 2, roots, L))

# ───────────────────────────────────────────────────────────────────────────────
# 3. INTERACTIVE “MAIN”
# ───────────────────────────────────────────────────────────────────────────────
def main():
    roots = compute_roots()
    L     = compute_L(roots)

    print("Prime Search Options:")
    print(" 1) Find all primes in an integer range")
    print(" 2) Find all primes of a given size (bits or decimal digits)")
    choice = input("Enter 1 or 2: ").strip()

    if choice == "1":
        lo = int(input("Enter lower bound of range: ").strip())
        hi = int(input("Enter upper bound of range: ").strip())
        primes = [n for n in range(lo, hi+1)
                  if is_prime_wheel(n, roots, L)]
        print(f"\nPrimes in [{lo}, {hi}]:\n{primes}")

    elif choice == "2":
        mode_input = input(
            "Enter bit-length or decimal-digit length.\n"
            "Prefix with 'd ' for digits (e.g. 'd 4'),\n"
            "!!! Warning entering more than d 8 or more than 24 bits may take a while. !!!\n"
            "Type the number of bits or d [int] (e.g. '256' → bits or d 6): "
        ).strip().lower()

        if mode_input.startswith("d"):
            parts = mode_input.split()
            d = int(parts[1])
            lo, hi = 10**(d-1), 10**d - 1
            descriptor = f"{d}-digit"
        else:
            parts = mode_input.split()
            if parts[0] in ("bits", "b") and len(parts) == 2:
                b = int(parts[1])
            else:
                b = int(parts[0])
            lo, hi = 1 << (b-1), (1 << b) - 1
            descriptor = f"{b}-bit"

        primes = [n for n in range(lo, hi+1)
                  if is_prime_wheel(n, roots, L)]
        print(f"\nPrimes with {descriptor} length in [{lo}, {hi}]:\n{primes}")

    else:
        print("Invalid choice; exiting.")
        return

    cnt      = len(primes)
    twin_cnt = sum(1 for p in primes if (p + 2) in primes)
    print(f"\nTotal primes found: {cnt}")
    print(f"Twin-prime pairs: {twin_cnt}")

if __name__ == "__main__":
    main()
