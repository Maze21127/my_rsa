import math
import random


def is_co_prime(p, q):
    return math.gcd(p, q) == 1


def modular(p, q):
    euler = (p - 1) * (q - 1)

    while True:
        e = random.randrange(7, 65537)
        if is_co_prime(e, euler):
            break

    _, x, y = extend_gcd(e, euler)

    if x < 0:
        x += euler
    d = x

    return d, e


def extend_gcd(a: int, b: int):
    x = 0
    y = 1
    lx = 1
    ly = 0
    old_a = a
    old_b = b
    while b != 0:
        q = a // b
        (a, b) = (b, a % b)
        (x, lx) = ((lx - (q * x)), x)
        (y, ly) = ((ly - (q * y)), y)
    if lx < 0:
        lx += old_b
    if ly < 0:
        ly += old_a
    return a, lx, ly


def inverse(x: int, n: int):
    (divider, inv, _) = extend_gcd(x, n)
    return inv


def inverse2(x: int, n: int):
    return x % n
