import socket
import threading
import time
import struct
import logging
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto import Random
from Crypto.Cipher import AES

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

        serv.listen(concurrenctcons)

        self.Socket = serv

    def Start(self):
        self.Logger.info("Listening for connections...")

        while True: # listening loop
            (clientsock, addr) = self.Socket.accept()
            threading.Thread(target=self.HandleClient,args=(clientsock, addr)).start()


    def PerformKeyExchange(self, socket):
        clientpubkeybytes = socket.recv(120)

        try:
            clientpubkey = serialization.load_der_public_key(
                clientpubkeybytes,
                default_backend()
            )
        except ValueError:
            self.Logger.error("Recieved invalid public key, closing connection")
            socket.close()
            return None

        priv = ec.generate_private_key(
            ec.SECP384R1(),
            default_backend()
        )

        pubkey = priv.public_key().public_bytes(
            encoding = serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.Logger.info("sending key %s..."%(pubkey[:10]))

        socket.send(pubkey)




        sharedkey = priv.exchange(
            ec.ECDH(),
            clientpubkey
        )

        return HKDF(
            algorithm = hashes.SHA256(),
            length=32,
            salt = None,
            info = b'handshake data',
            backend = default_backend()
        ).derive(
            sharedkey
        )

    def DecryptRecievedData(self, data, key):
        IV = data[:AES.block_size]


        if(len(data) == 0 or len(data) % AES.block_size != 0):
            self.Logger.error("Invalid bytes recieved, closing connection")
            return None

        aes = AES.new(
            key,
            AES.MODE_CBC,
            IV
        )


        dec_dat = aes.decrypt(data[AES.block_size:])

        if(len(dec_dat) == 0):
            self.Logger.error("Empty data after IV, closing connection")
            return None

        padding = int(dec_dat[-1])

        return dec_dat[:-padding]


    def DecodeStruct(self, structbytes, fmt):
        if(len(structbytes) != struct.calcsize(fmt)):
            self.Logger.error("Incorrect struct length, closing connection")
            return None

        return struct.unpack(fmt ,bytearray(structbytes))


    def HandleClient(self, socket, addr):
        blocks = b''

        self.Logger.info("connected client on: %s"%(str(addr)))
        #now recieve client key

        derived = self.PerformKeyExchange(socket)

        if not derived: return

        self.Logger.info("derived key: %s..."%(derived[:10]))



        while True: #read all data
            block = socket.recv(512)
            if block == b'':
                break
            blocks += block


        dec = self.DecryptRecievedData(blocks, derived)
        
        if not dec: socket.close(); return

        fmt = "!3si"

        tp = self.DecodeStruct(dec, fmt)

        if not tp: socket.close(); return

        self.Logger.info("Client %s sent %s"%(str(addr), tp))


if __name__ == "__main__":
    serv = Server('0.0.0.0',13371,5)
    serv.Start()