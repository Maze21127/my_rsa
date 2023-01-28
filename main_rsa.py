import base64
import os
import sys

import my_rsa
from my_rsa import utils


# pubkey, privkey = my_rsa.key.new_keys(512)
# privkey.export_pkcs("rsapriv.DER")
# pubkey.export_pkcs("prsapub.DER")
# message = "🎲 roll the bones 🎲"
#
# pubkey = my_rsa.key.PublicKey.import_pkcs('prsapub.DER')
# encrypted = my_rsa.RSA.RSA.encrypt(message, pubkey)
# print(encrypted)
# print(base64.b64encode(encrypted.encode()).decode('utf-8'))
#
#
# privkey = my_rsa.key.PrivateKey.import_pkcs('rsapriv.DER')
# dec = my_rsa.RSA.RSA.decrypt(encrypted, privkey)
# print(dec)


def test_key_creations():
    pubkey, privkey = my_rsa.key.new_keys(512)
    pubkey.export_pkcs(f"keys/test_pub.DER")
    privkey.export_pkcs(f"keys/test_priv.DER")
    return True


def test_encrypt():
    pubkey = my_rsa.key.PublicKey.import_pkcs(f"keys/test_pub.DER")
    message = utils.load_message('test2.txt')
    encrypted = my_rsa.RSA.RSA2.encrypt(message, pubkey)
    print(encrypted)
    utils.save_message(encrypted, 'test')
    return True


def test_decrypt():
    priv = my_rsa.key.PrivateKey.import_pkcs(f"keys/test_priv.DER")
    encrypted = utils.load_message('test')
    dec = my_rsa.RSA.RSA2.decrypt(encrypted, priv)
    print(dec)
    return True


#assert test_key_creations() == True
assert test_encrypt() == True
assert test_decrypt() == True

sys.exit(0)

print("Welcome to my RSA implementation")
while True:
    action = input("Введите команду:\n1-Создать ключи\n2-Зашифровать сообщение\n3-Расшифровать сообщение\n4-Выход\n")
    if action not in ("1", "2", "3", "4"):
        print("Такой команды нет")
        continue

    if action == '4':
        sys.exit(0)

    if action == '1':
        try:
            keysize = int(input("Выберите размер ключей: 64/128/256/512/1024/2048\n"))
        except ValueError:
            print("Ошибка, неверный размер ключей")
            sys.exit(-1)
        if keysize not in (64, 128, 256, 512, 1024, 2048):
            print("Ошибка, неверный размер ключей")
            sys.exit(-1)
        pubkey, privkey = my_rsa.key.new_keys(keysize)
        keyholder = input("Введите название файлов ключей: ")
        pubkey.export_pkcs(f"keys/{keyholder}_pub.DER")
        privkey.export_pkcs(f"keys/{keyholder}_priv.DER")
        print("Ключи сохранены")

    elif action == '2':
        text_action = input("Как будете загружать сообщение?\n1-Из командной строки\n2-Из файла\n")
        while text_action not in ("1", "2"):
            print("Неизвестная команда")
            text_action = input("Как будете загружать сообщение?\n1-Из командной строки\n2-Из файла\n")
        if text_action == '1':
            message = input("Введите сообщение\n")
        if text_action == '2':
            file = input("Укажите путь к сообщению: ")
            message = utils.load_message(file)
        print("Укажите название публичного ключа (должен находиться в папке keys)")
        print(f"Доступные ключи: {', '.join(filter(lambda x: 'pub' in x, os.listdir('keys')))}")
        keyfile = input()
        pubkey = my_rsa.key.PublicKey.import_pkcs(f"keys/{keyfile}")
        encrypted = my_rsa.RSA.RSA2.encrypt(message, pubkey)
        print(encrypted)
        save_action = input("Сохранить?(yes/no)")
        while save_action not in ("yes", "no"):
            save_action = input("Введите yes или no")
        if save_action == "yes":
            message_file = input("Введите название файла, куда сохранить сообщение: ")
            utils.save_message(encrypted, message_file)
    elif action == '3':
        print("Укажите название приватного ключа (должен находиться в папке keys)")
        print(f"Доступные ключи: {', '.join(filter(lambda x: 'priv' in x, os.listdir('keys')))}")
        keyfile = input()
        encrypted_file = input("Укажите путь к зашифрованному сообщению: ")
        encrypted = utils.load_message(encrypted_file)
        privkey = my_rsa.key.PrivateKey.import_pkcs(f"keys/{keyfile}")
        dec = my_rsa.RSA.RSA2.decrypt(encrypted, privkey)
        print(dec)
