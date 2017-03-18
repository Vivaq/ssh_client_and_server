import socket
import json
import subprocess
from subprocess import PIPE
from AES import *
from RSA import *


class Server(object):

    def __init__(self):
        self.aes = AES_Module()
        self.rsa = RSA_Module()
        #self.sharedPrime = 536  # p
        #self.sharedBase = 5
        self.sharedPrime = long('B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371', 16)
        self.sharedBase = long('A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5', 16)
        self.serverSecret = 123  # b
        self.B = (self.sharedBase ** self.serverSecret) % self.sharedPrime
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_address = ('localhost', 2222)
        self.sock.bind(self.server_address)
        self.sock.listen(1)
        self.private_key, self.public_key = self.rsa.generate_RSA()
        self.client_public_key = ''
        self.rand = 1
        self.username = ''
        self.key = ''
        self.sub = subprocess.Popen('/bin/bash', stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=False)

    def start_listening(self):
        while True:

            print('waiting for a connection')
            connection, client_address = self.sock.accept()
            try:
                print('connection from', client_address)

                while True:
                    data = connection.recv(1000)
                    print('received "%s"' % data)

                    if data.split('#')[0] == 'AES':                       #Procedura uzgodnienia klucza miedzy klienetem a serwerem
                        print('sending key back to the client')
                        A = data.split('#')[1]

                        serverSharedSecret = (long(A) ** self.serverSecret) % self.sharedPrime

                        self.key = hashlib.sha256(str(serverSharedSecret)).digest() #mam klucz aesowy, taki sam obliczy sobie klient

                        signed_B = self.rsa.sign_data(self.private_key, str(self.B))

                        connection.sendall(str(self.B) + '#' + str(signed_B))
                        print base64.b64encode(self.key)


                    elif data.split('#', 1)[0] == 'PUB':
                        self.client_public_key = data.split('#', 1)[1]

                    elif data.split('#')[0] == 'FDF':
                        encrypted_A = data.split('#', 1)[1]
                        A = self.rsa.decrypt_RSA(self.private_key, encrypted_A)
                        serverSharedSecret = (long(A) ** self.serverSecret) % self.sharedPrime

                        key = hashlib.sha256(str(serverSharedSecret)).digest()
                        encrypted_B = self.rsa.encrypt_RSA(self.client_public_key, str(self.B))

                        connection.sendall(encrypted_B)
                        print base64.b64encode(key)

                    elif data.split('#')[0] == 'Challange':

                        challange = data.split('#', 1)[1]
                        signature = self.rsa.sign_data(self.private_key, str(challange))
                        message = str(signature) + '#' + str(self.public_key)
                        connection.sendall(message)

                    elif data.split('#')[0] == "KeyAuthorize":
                        with open('server_keys') as f:
                            keys = json.load(f)
                        p_key = keys[self.username]
                        rand = randint(0, 1000)
                        msg = self.rsa.encrypt_RSA(p_key, str(rand))
                        connection.sendall(msg)

                    elif data.split('#', 1)[0] == "Hash":

                        stg = str(rand)
                        hash_compare = hashlib.sha256(stg).digest()

                        if hash_compare == (data.split('#', 1)[1]):
                            connection.sendall("Authorization succesfull")
                        else:
                            connection.sendall("Fail")
                            connection.shutdown()


                    elif data.split('#')[0] == 'User':
                        with open('server_passwords') as f:
                            abc = json.load(f)
                        try:
                            a = abc[data.split('#')[1]]
                            self.username = data.split('#')[1]
                            print self.username
                            connection.sendall('Uzytkownik istnieje')
                        except:
                            connection.sendall('Fail')
                            connection.shutdown()


                    elif data.split('#',1)[0] == 'PassAuthorize':
                        with open('server_passwords') as f:
                            passwords = json.load(f)

                        try:
                            passw = passwords[self.username]

                            h_passw = hashlib.sha256(passw).digest()
                            if h_passw == data.split('#', 1)[1]:
                                try:
                                    connection.sendall("Authorization succesfull") #tu socket sie wypieprza
                                except Exception as e:
                                    print e
                                    connection.shutdown()
                            else:
                                connection.sendall("Fail")
                                connection.shutdown()
                        except:
                            connection.shutdown()


                    elif data:                                               #procedura wymiany szyfrowanych danych
                        output = ''
                        message = self.aes.decrypt(self.key, data)
                        self.sub.stdin.write(message + '\n')
                        self.sub.stdin.write('echo afweaf\n')
                        while True:
                            a = self.sub.stdout.readline()
                            if not a == 'afweaf\n':
                                output = output + a
                            else:
                                break
                        reply = self.aes.encrypt(self.key,output)
                        connection.sendall(reply)
                        print output
                    else:
                        print('no more data from', client_address)
                        break

            except Exception as e:
                print e
                continue


if __name__ == '__main__':
    server = Server()
    server.start_listening()