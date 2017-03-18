import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import string
import random
from random import randint


class AES_Module(object):

    def id_generator(self, chars=string.ascii_letters + string.digits):
        size = randint(5, 15)
        return ''.join(random.choice(chars) for _ in range(size))

    def generate_key(self):
        Pass = self.id_generator()
        encodedPass = hashlib.sha256(Pass).digest()
        print base64.b64encode(encodedPass)
        return encodedPass

    def pad(self, message):
        #message = raw_input('MESSAGE: ')
        length = 16 - (len(message) % 16)
        message += '{'*length
        return message

    def encrypt(self, encodedPass, message):
        EncryptData = AES.new(encodedPass, AES.MODE_ECB)
        message = self.pad(message)
        ciphertext = EncryptData.encrypt(message)
        return base64.b64encode(ciphertext)

    def decrypt(self, encodedPass, cipher):
        DecryptData = AES.new(encodedPass, AES.MODE_ECB)
        plaintext = DecryptData.decrypt(base64.b64decode(cipher))
        l = plaintext.count('{')
        return plaintext[:len(plaintext)-l]







