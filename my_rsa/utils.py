import math
import os

from my_rsa.prime import get_random_prime
from my_rsa.rsa_math import inverse


def ceil_div(n: int, div: int):
    quanta, mod = divmod(n, div)
    if mod:
        quanta += 1
    return quanta


def byte_size(n: int):
    if n == 0:
        return 1
    return ceil_div(n.bit_length(), 8)


def pad_for_encryption(message: str, target_len: int):
    msglength = len(message)

    # Получаем сдвиг
    padding = b""
    padding_length = target_len - msglength - 3

    # Продолжаем добавлять данные, пока не получим необходимую длину.
    while len(padding) < padding_length:
        needed_bytes = padding_length - len(padding)

        # Всегда читаем как минимум на 8 байт больше, чем нам нужно, и обрезаем остальные
        # послу удаления нулевого байта это увеличивает шанс получить достаточно байтов.
        new_padding = os.urandom(needed_bytes + 5)
        new_padding = new_padding.replace(b"\x00", b"")
        padding = padding + new_padding[:needed_bytes]

    return b"".join([b"\x00\x02", padding, b"\x00", message])


def int2bytes(number: int, size=0):
    bytes_required = max(1, math.ceil(number.bit_length() / 8))
    if size > 0:
        return number.to_bytes(size, "big")

    return number.to_bytes(bytes_required, "big")


def _initial_blinding_factor(n: int):
    return get_random_prime(n.bit_length())


def _update_blinding_factor(n: int):
    blindfac = _initial_blinding_factor(n)
    blindfac_inverse = inverse(blindfac, n)
    if blindfac < 0:
        blindfac = _initial_blinding_factor(n)
        blindfac_inverse = inverse(blindfac, n)
    else:
        # Переиспользуем предыдущие вычисления.
        blindfac = pow(blindfac, 2, n)
        blindfac_inverse = pow(blindfac_inverse, 2, n)

    return blindfac, blindfac_inverse


def blind(encrypted, priv_key):
    blindfac, blindfac_inverse = _update_blinding_factor(priv_key.n)
    blinded = (encrypted * pow(blindfac, priv_key.e, priv_key.n)) % priv_key.n
    return blinded, blindfac_inverse


def blinded_decrypt(priv_key, encrypted):
    blinded, blindfac_inverse = blind(encrypted, priv_key)

    s1 = pow(blinded, priv_key.exp1, priv_key.p)
    s2 = pow(blinded, priv_key.exp2, priv_key.q)
    h = ((s1 - s2) * priv_key.coefficient) % priv_key.p
    decrypted = s2 + priv_key.q * h

    return (blindfac_inverse * decrypted) % priv_key.n


def save_message(message, filename):
    with open(filename, 'w') as file:
        file.write(message)


def load_message(filename):
    try:
        with open(filename, 'r') as file:
            message = "".join(file.readlines())
    except FileNotFoundError:
        return "File not found"
    return message
