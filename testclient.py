#!/usr/bin/env python3
import socket
import struct 
import array
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from Crypto import Random
from Crypto.Cipher import AES
from hexdump import hexdump

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect(('localhost', 13371))


fmt  = "!3siii"

buf = bytearray(struct.calcsize(fmt)+4+len(fmt))

struct.pack_into("!i%ss"%len(fmt),buf,0,len(fmt),fmt.encode('UTF-8'))

struct.pack_into(fmt,buf,4+len(fmt),'cus'.encode('UTF-8'),2,5,7)

privkey = peer_public_key = ec.generate_private_key(
    ec.SECP384R1(), 
    default_backend()
)

sock.send(
    privkey.public_key().public_bytes(
        serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
)

servpubkeybytes = sock.recv(120)


servpubkey = serialization.load_der_public_key(
    servpubkeybytes,
    default_backend()
)


sharedkey = privkey.exchange(
    ec.ECDH(),
    servpubkey
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

IV = Random.new().read(AES.block_size)

aes = AES.new(
    derived,
    AES.MODE_CBC,
    IV
)

padding = AES.block_size - len(buf) % AES.block_size

buf += bytes([padding]) * padding

print("Derived key: ")
hexdump(derived)
encd = IV + aes.encrypt(buf)

print("Sending %s bytes:"%(len(encd)))
hexdump(encd)

sock.send(encd)
