import socket
import threading
import time
import struct
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
import logging
from cryptography.hazmat.primitives import ec

class Server:
    def __init__(self,host, port, concurrenctcons):
        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        serv.bind((host,port))


        logger = logging.getLogger(__name__)

        logger.setLevel(logging.INFO)

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        self.Logger = logger

        self.InitCrypto()

        serv.listen(concurrenctcons)

        self.Socket = serv


    def InitCrypto(self):
        self.Logger.info("Generating RSA key...")
        key = RSA.generate(4096)

        self.Key = key
        self.Decryptor = PKCS1_v1_5.new(key)

    def Start(self):
        self.Logger.info("Listening for connections...")

        while True: # listening loop
            (clientsock, addr) = self.Socket.accept()
            threading.Thread(target=self.HandleClient,args=(clientsock, addr)).start()


    def HandleClient(self, socket, addr):
        blocks = b''

        self.Logger.info("connected client on: %s"%(str(addr)))

        pubkey = self.Key.publickey().exportKey('DER')

        self.Logger.info("sending key %s... to %s"%(pubkey[:10],str(addr)))

        socket.send(pubkey)


        while True:
            block = socket.recv(512)
            if block == b'':
                break
            blocks += block

        if len(blocks) != 512:
            socket.close()
            self.Logger.error("Incorrect recieve format, closing socket for %s"%(str(addr)))
            return
        dec = self.Decryptor.decrypt(blocks, b'\xdeadbeef')


        if(len(dec) != 7):
            socket.close()
            self.Logger.error("Incorrect struct length, closing socket for %s"%(str(addr)))
            return

        tp = struct.unpack("!3si",bytearray(dec))

        self.Logger.info("Client %s sent %s"%(str(addr), tp))


if __name__ == "__main__":
    serv = Server('0.0.0.0',13371,5)
    serv.Start()