#!/usr/bin/env python3
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
from hexdump import hexdump

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

        self.Logger.info("Struct with padding:")
        hexdump(dec_dat)

        padding = int(dec_dat[-1])

        return dec_dat[:-padding]


    def DecodeStruct(self, structbytes):
        formatlen = struct.unpack('!i',structbytes[:4])[0]

        fmt = struct.unpack('!%ss'%formatlen,structbytes[4:4+formatlen])[0]

        structsize = struct.calcsize(fmt)	
	
        return struct.unpack(fmt ,bytearray(structbytes[4+formatlen:]))


    def HandleClient(self, socket, addr):
        blocks = b''

        self.Logger.info("connected client on: %s"%(str(addr)))
        #now recieve client key

        derived = self.PerformKeyExchange(socket)

        if not derived: return

        self.Logger.info("derived key: ")
        hexdump(derived)


        while True: #read all data
            block = socket.recv(512)
            if block == b'':
                break
            blocks += block

        self.Logger.info("got data: ")
        hexdump(blocks)


        dec = self.DecryptRecievedData(blocks, derived)
        
        if not dec: socket.close(); return

        tp = self.DecodeStruct(dec)

        if not tp: socket.close(); return

        self.Logger.info("Client %s sent: %s, with dump:"%(str(addr), tp))
        self.DetermineCommand(tp[0].decode('utf-8'))(*tp[1:])


    def Lowerlights(self, amount):
        print("LOWERING LIGHTS BY %s"%amount)

    def TurnOffLights(self):
        print("Turning off lights")

    def DetermineCommand(self, cmdstring):
        if cmdstring == 'low':
            return self.Lowerlights
        elif cmdstring == 'off':
            return self.TurnOffLights
            


if __name__ == "__main__":
    serv = Server('0.0.0.0',13371,5)
    serv.Start()
