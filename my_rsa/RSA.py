import base64

from rsa.key import PublicKey, PrivateKey

from my_rsa import utils


class RSA:
    @staticmethod
    def encrypt(plain_text, key: PublicKey):
        # keylength = utils.byte_size(key.n)
        # padded = utils.pad_for_encryption(plain_text.encode('utf-8'), keylength)
        # payload = int.from_bytes(padded, "big")
        # enc = pow(payload, key.e, key.n)
        # block = utils.int2bytes(enc, keylength)
        cipher = ""
        for c in plain_text:
            m = ord(c)
            cipher += str(pow(m, key.e, key.n)) + " "
        return base64.b64encode(cipher.encode()).decode('utf-8')

    @staticmethod
    def decrypt(crypted_text, key: PrivateKey):
        # blocksize = utils.byte_size(key.n)
        # encrypted = int.from_bytes(crypted_text, "big", signed=False)
        # decrypted = utils.blinded_decrypt(key, encrypted)
        # cleartext = utils.int2bytes(decrypted, blocksize)
        # sep_idx = cleartext.find(b"\x00", 2)
        #
        # return cleartext[sep_idx + 1:]
        crypted_text = base64.b64decode(crypted_text).decode('utf-8')
        message = ""
        for part in crypted_text.split():
            if part:
                result = pow(int(part), key.d, key.n)
                message += chr(result)

        return message