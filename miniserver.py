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
from queue import Queue
from lightcontroller import light_controller


class light_server:
    def __init__(self, host, port, concurrenctcons):
        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        serv.bind((host, port))

        logger = logging.getLogger(__name__)

        logger.setLevel(logging.INFO)

        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = logging.Formatter(
            "[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
        ch.setFormatter(formatter)
        logger.addHandler(ch)

        self.logger = logger
        self.Socket = serv
        self.command_queue = Queue()

        self.lc = light_controller('config.json')

        serv.listen(concurrenctcons)

    def start(self):
        self.logger.info("Listening for connections...")

        threading.Thread(target=self.queue_processor, daemon=True).start()

        while True:  # listening loop
            (clientsock, addr) = self.Socket.accept()
            threading.Thread(
                target=self.handle_client, args=(
                    clientsock, addr), daemon=True).start()

    def queue_processor(self):
        while True:
            cmd = self.command_queue.get(block=True)
            self.determine_command(cmd[0].decode('utf-8'))(*cmd[1:])

    def perform_key_exchange(self, socket):
        clientpubkeybytes = socket.recv(120)

        try:
            clientpubkey = serialization.load_der_public_key(
                clientpubkeybytes,
                default_backend()
            )
        except ValueError:
            self.logger.error(
                "Recieved invalid public key, closing connection")
            socket.close()
            return None

        priv = ec.generate_private_key(
            ec.SECP384R1(),
            default_backend()
        )

        pubkey = priv.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        self.logger.info("sending key %s..." % (pubkey[:10]))

        socket.send(pubkey)

        sharedkey = priv.exchange(
            ec.ECDH(),
            clientpubkey
        )

        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(
            sharedkey
        )

    def decrypt_recieved_data(self, data, key):
        IV = data[:AES.block_size]

        if(len(data) == 0 or len(data) % AES.block_size != 0):
            self.logger.error("Invalid bytes recieved, closing connection")
            return None

        aes = AES.new(
            key,
            AES.MODE_CBC,
            IV
        )

        dec_dat = aes.decrypt(data[AES.block_size:])

        if(len(dec_dat) == 0):
            self.logger.error("Empty data after IV, closing connection")
            return None

        self.logger.info("Struct with padding:")
        hexdump(dec_dat)

        padding = int(dec_dat[-1])

        return dec_dat[:-padding]

    def decode_struct(self, structbytes):
        formatlen = struct.unpack('!i', structbytes[:4])[0]

        fmt = struct.unpack('!%ss' %
                            formatlen, structbytes[4:4 + formatlen])[0]

        structsize = struct.calcsize(fmt)

        return struct.unpack(fmt, bytearray(structbytes[4 + formatlen:]))

    def handle_client(self, socket, addr):
        blocks = b''

        self.logger.info("connected client on: %s" % (str(addr)))
        # now recieve client key

        derived = self.perform_key_exchange(socket)

        if not derived:
            return

        self.logger.info("derived key: ")
        hexdump(derived)

        while True:  # read all data
            block = socket.recv(512)
            if block == b'':
                break
            blocks += block

        self.logger.info("got data: ")
        hexdump(blocks)

        dec = self.decrypt_recieved_data(blocks, derived)

        if not dec:
            socket.close()
            return

        tp = self.decode_struct(dec)

        if not tp:
            socket.close()
            return

        self.logger.info("Client %s sent: %s" % (str(addr), tp))

        self.command_queue.put(tp, block=True)

    def determine_command(self, cmdstring):
        if cmdstring == 'int':
            return self.lc.set_light_intensity
        elif cmdstring == 'tmp':
            return self.lc.set_light_temperature
        else:
            raise Exception("ffs")

if __name__ == "__main__":
    serv = light_server('0.0.0.0', 13371, 5)
    serv.start()