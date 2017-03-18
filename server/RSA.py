from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from base64 import b64decode, b64encode


class RSA_Module(object):

    def generate_RSA(self,bits=2048):
        '''
        Generate an RSA keypair with an exponent of 65537 in PEM format
        param: bits The key length in bits
        Return private key and public key
        '''
        new_key = RSA.generate(bits, e=65537)
        public_key = new_key.publickey().exportKey("PEM")
        private_key = new_key.exportKey("PEM")
        return private_key, public_key

    def encrypt_RSA(self,public_key, message):
        '''
        param: public_key_loc Path to public key
        param: message String to be encrypted
        return base64 encoded encrypted string
        '''
        rsakey = RSA.importKey(public_key)
        rsakey = PKCS1_OAEP.new(rsakey)
        encrypted = rsakey.encrypt(message)
        return encrypted.encode('base64')


    def decrypt_RSA(self,private_key, package):
        '''
        param: public_key_loc Path to your private key
        param: package String to be decrypted
        return decrypted string
        '''
        rsakey = RSA.importKey(private_key)
        rsakey = PKCS1_OAEP.new(rsakey)
        decrypted = rsakey.decrypt(b64decode(package))
        return decrypted

    def sign_data(self, private_key, data):
        data = b64encode(str(data))
        rsakey = RSA.importKey(private_key)
        signer = PKCS1_v1_5.new(rsakey)
        digest = SHA256.new()
        # It's being assumed the data is base64 encoded, so it's decoded before updating the digest
        digest.update(b64decode(data))
        sign = signer.sign(digest)
        return b64encode(sign)

    def verify_sign(self, public_key, signature, data):
        data = b64encode(str(data))
        rsakey = RSA.importKey(public_key)
        signer = PKCS1_v1_5.new(rsakey)
        digest = SHA256.new()
        # Assumes the data is base64 encoded to begin with
        digest.update(b64decode(data))
        if signer.verify(digest, b64decode(signature)):
            return True
        return False