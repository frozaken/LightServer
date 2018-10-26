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


    def HandleClient(self, socket, addr):
        blocks = b''

        self.Logger.info("connected client on: %s"%(str(addr)))

        priv = ec.generate_private_key(
            ec.SECP384R1(),
            default_backend()
        )

        pubkey = priv.public_key().public_bytes(
            encoding = serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.Logger.info("sending key %s... to %s"%(pubkey[:10],str(addr)))

        socket.send(pubkey)


        #now recieve client key

        clientpubkeybytes = socket.recv(120)

        clientpubkey = serialization.load_der_public_key(
            clientpubkeybytes,
            default_backend()
        )


        sharedkey = priv.exchange(
            ec.ECDH(),
            clientpubkey
        )

        derived = HKDF(
            algorithm = hashes.SHA256(),
            length=32,
            salt = None,
            info = b'handshake data',
            backend = default_backend()
        ).derive(
            sharedkey
        )

        self.Logger.info("derived key: %s..."%(derived[:10]))

        while True:
            block = socket.recv(512)
            if block == b'':
                break
            blocks += block


        IV = blocks[:AES.block_size]

        aes = AES.new(
            derived,
            AES.MODE_CBC,
            IV
        )


        dec_dat = aes.decrypt(blocks[AES.block_size:])

        padding = int(dec_dat[-1])

        final = dec_dat[:-padding]

        fmt = "!3si"

        if(len(final) != struct.calcsize(fmt)):
            socket.close()
            self.Logger.error("Incorrect struct length, closing socket for %s"%(str(addr)))
            return

        tp = struct.unpack(fmt ,bytearray(final))

        self.Logger.info("Client %s sent %s"%(str(addr), tp))


if __name__ == "__main__":
    serv = Server('0.0.0.0',13371,5)
    serv.Start()