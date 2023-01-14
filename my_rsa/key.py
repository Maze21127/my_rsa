import base64
from abc import ABC

from pyasn1.codec.der import encoder, decoder
from pyasn1.type import univ, namedtype

from my_rsa import rsa_math
from my_rsa.rsa_math import modular, extend_gcd
from my_rsa.prime import get_random_prime


class AsnPrivateKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("modulus", univ.Integer()),
        namedtype.NamedType("privateExponent", univ.Integer()),
        namedtype.NamedType("publicExponent", univ.Integer()),
        namedtype.NamedType("prime1", univ.Integer()),
        namedtype.NamedType("prime2", univ.Integer()),
        namedtype.NamedType("exponent1", univ.Integer()),
        namedtype.NamedType("exponent2", univ.Integer()),
        namedtype.NamedType("coefficient", univ.Integer()),
    )


class AsnPublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType("modulus", univ.Integer()),
        namedtype.NamedType("publicExponent", univ.Integer()),
    )


class AbstractKey:
    def __init__(self, n: int, e: int) -> None:
        self.n = n
        self.e = e

    def export_pkcs(self, keyfile):
        """Экспорт ключа в DER"""
        raise NotImplementedError("Abstract method need to be implemented")

    @classmethod
    def import_pkcs(cls, keyfile):
        """Импорт DER ключа"""
        raise NotImplementedError("Abstract method need to be implemented")


class PublicKey(AbstractKey, ABC):
    def __str__(self) -> str:
        return f'PublicKey({self.n}, {self.e})'

    def export_pkcs(self, keyfile):
        asn_key = AsnPublicKey()
        asn_key.setComponentByName("modulus", self.n)
        asn_key.setComponentByName("publicExponent", self.e)

        with open(keyfile, 'w') as file:
            file.write(f"""-----BEGIN PUBLIC KEY-----
{base64.b64encode(encoder.encode(asn_key)).decode()}
-----END PUBLIC KEY-----""")
        return True

    @classmethod
    def import_pkcs(cls, keyfile):
        with open(keyfile, 'r') as file:
            string = file.readlines()[1]
            pub = base64.b64decode(string)
        public_key, _ = decoder.decode(pub, asn1Spec=AsnPublicKey())
        return cls(n=int(public_key['modulus']),
                   e=int(public_key['publicExponent']))


class PrivateKey(AbstractKey, ABC):
    def __init__(self, n: int, e: int, d: int, p: int, q: int):
        super().__init__(n, e)
        self.d = d
        self.p = p
        self.q = q
        self.exp1 = int(d % (p - 1))
        self.exp2 = int(d % (q - 1))
        self.coefficient = rsa_math.inverse(q, p)

    def __str__(self) -> str:
        return f'PrivateKey({self.n}, {self.e}, {self.d}, {self.p}, {self.q})'

    def export_pkcs(self, keyfile):
        asn_key = AsnPrivateKey()
        asn_key.setComponentByName("modulus", self.n)
        asn_key.setComponentByName("privateExponent", self.d)
        asn_key.setComponentByName("publicExponent", self.e)
        asn_key.setComponentByName("prime1", self.p)
        asn_key.setComponentByName("prime2", self.q)
        asn_key.setComponentByName("exponent1", self.exp1)
        asn_key.setComponentByName("exponent2", self.exp2)
        asn_key.setComponentByName("coefficient", self.coefficient)

        with open(keyfile, "w") as file:
            file.write(f"""-----BEGIN PRIVATE KEY-----
{base64.b64encode(encoder.encode(asn_key)).decode()}
-----END PRIVATE KEY-----""")
        return True

    @classmethod
    def import_pkcs(cls, keyfile):
        with open(keyfile, 'r') as file:
            string = file.readlines()[1]
            priv = base64.b64decode(string)
        private_key, _ = decoder.decode(priv, asn1Spec=AsnPrivateKey())
        return cls(n=int(private_key['modulus']),
                   e=int(private_key['publicExponent']),
                   d=int(private_key['privateExponent']),
                   p=int(private_key['prime1']),
                   q=int(private_key['prime2']))


def new_keys(bits: int = 1024) -> tuple[PublicKey, PrivateKey]:
    p = get_random_prime(bits // 2)
    q = get_random_prime(bits // 2)
    n = p * q
    if n.bit_length() != bits:
        return new_keys(bits)
    d, e = modular(p, q)

    return PublicKey(n, e), PrivateKey(n, e, d, p, q)

