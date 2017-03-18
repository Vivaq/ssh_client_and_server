import socket
from AES import *
from RSA import *

class Client(object):

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.aes = AES_Module()
        self.rsa = RSA_Module()
        self.key = ''
        #self.sharedPrime = 536
        #self.sharedBase = 5
        self.sharedPrime = long('B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371', 16)
        self.sharedBase = long('A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5', 16)
        self.clientSecret = 234
        self.private_key = ''
        self.public_key = ''
        self.auth_index = 1
        self.is_client_authorized = False
        self.is_server_authorized = False
        self.server_public_key = ''
        self.private_key, self.public_key = self.rsa.generate_RSA()


    def connect_to_server(self, address, port):
        server_address = (address, port)
        self.sock.connect(server_address)


    def negotiate_key(self):                                # Procedura uzgodnienia klucza z serwerem
        A = (self.sharedBase ** self.clientSecret) % self.sharedPrime
        message = 'AES#' + str(A)
        self.sock.sendall(message)
        B = self.sock.recv(1000)
        veryfied_B = self.rsa.verify_sign(self.server_public_key, B.split('#', 1)[1], B.split('#', 1)[0])
        if veryfied_B:
            clientSharedSecret = (long(B.split('#', 1)[0]) ** self.clientSecret) % self.sharedPrime
            self.key = hashlib.sha256(str(clientSharedSecret)).digest()


    def diffie_helman_fixed(self):
        abcde = 'PUB#' + str(self.public_key)
        self.sock.sendall(abcde)
        A = (self.sharedBase ** self.clientSecret) % self.sharedPrime
        encrypted_A = self.rsa.encrypt_RSA(self.server_public_key, str(A))
        message = 'FDF#' + str(encrypted_A)
        self.sock.sendall(message)

        encrypted_B = self.sock.recv(1000)
        B = self.rsa.decrypt_RSA(self.private_key, encrypted_B)
        clientSharedSecret = (long(B) ** self.clientSecret) % self.sharedPrime
        self.key = hashlib.sha256(str(clientSharedSecret)).digest()
        print base64.b64encode(self.key)


    def start_exchange(self, message):
        # Send data
        message = self.aes.encrypt(self.key, message)
        self.sock.sendall(message)

        data = self.sock.recv(10000)
        data = self.aes.decrypt(self.key, data)
        return data


    def register(self):
        self.private_key, self.public_key = self.rsa.generate_RSA()
        with open('priv_key', 'w') as f:
            f.write(self.private_key)
        message = 'Register#' + self.public_key
        self.sock.sendall(message)
        self.auth_index = self.sock.recv(1000)
        #with open('priv_key', 'a') as f:
            #f.write(self.auth_index)


    def authorize__server(self):
        challange = randint(1,1000)
        message = 'Challange#' + str(challange)
        self.sock.sendall(message)
        server_authentication = self.sock.recv(1000)
        signed_challange = server_authentication.split('#', 1)[0]
        certificate = server_authentication.split('#', 1)[1]
        self.server_public_key = certificate
        decrypted_challange = self.rsa.verify_sign(certificate, signed_challange, challange)
        if decrypted_challange:
            print 'zaufany server'
            self.is_server_authorized = True

    def check_user(self, username):
        user = 'User#' + username
        self.sock.sendall(user)
        reply = self.sock.recv(1000)
        if reply == "Fail":
            print "Nie ma takiego uzytkownika"
        else:
            print "istnieje uzytkownik"


    def key_authorize(self, key_file_name):
        with open(key_file_name) as f:
            self.private_key = f.read()
        message = 'KeyAuthorize'
        self.sock.sendall(message)
        auth_enc_string = self.sock.recv(1000)
        auth_string = self.rsa.decrypt_RSA(self.private_key, auth_enc_string)
        author_string = auth_string
        hash_string = hashlib.sha256(author_string).digest()
        message = 'Hash#' + hash_string
        self.sock.sendall(message)
        a = self.sock.recv(1000)
        if a == "Authorization succesfull":
            self.is_client_authorized = True
            print "autoryzacja ok"
        elif a == "Fail":
            print "bledny klucz"



    def pass_authorize(self, password):

        pass_hash = hashlib.sha256(password).digest()
        passw = 'PassAuthorize#' + str(pass_hash)
        self.sock.sendall(passw)
        reply = self.sock.recv(10000)
        if reply == "Fail":
            return "Bledne haslo"
        else:
            return "poprawne haslo"

    def close_connection(self):
        print('closing socket')
        self.sock.close()