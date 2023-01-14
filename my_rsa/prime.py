import random


def get_random_number(keysize=1024):
    return random.randrange(2 ** (keysize - 1), 2 ** keysize - 1)


def is_prime(n, k=5):
    if n < 2:
        return False
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]:
        if n % p == 0:
            return n == p
    s, d = 0, int(n - 1)
    while d % 2 == 0:
        s, d = s + 1, d // 2
    for i in range(k):
        x = pow(random.randint(2, n - 1), d, n)
        if x == 1 or x == n-1:
            continue
        for r in range(1, s):
            x = (x * x) % n
            if x == 1:
                return False
            if x == n-1:
                break
        else:
            return False
    return True


def get_random_prime(keysize=1024):
    number = get_random_number(keysize)
    while not is_prime(number):
        number = get_random_number(keysize)
    return number

