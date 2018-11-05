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

blksz = 6

sock.send(struct.pack("!i",blksz))

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


fmt  = "!3s0si"

buf = bytearray(blksz * AES.block_size)

struct.pack_into("!i%ss"%len(fmt),buf,0,len(fmt),fmt.encode('UTF-8'))

struct.pack_into(fmt,buf,4+len(fmt),'int'.encode('UTF-8'),''.encode("utf-8"),254)

padding = blksz * AES.block_size - len(buf)

buf += bytes([0]) * padding

print("Derived key: ")
hexdump(derived)
sock.send(IV)
print(IV)
encd = aes.encrypt(buf)

print("Sending %s bytes:"%(len(encd)))
hexdump(encd)

print("len: %s tar: %s"%(len(encd),blksz*AES.block_size))

sock.send(encd)

buf = bytearray(blksz * AES.block_size)

struct.pack_into("!i%ss"%len(fmt),buf,0,len(fmt),fmt.encode('UTF-8'))

struct.pack_into(fmt,buf,4+len(fmt),'int'.encode('UTF-8'),''.encode("utf-8"),0)

padding = blksz * AES.block_size - len(buf)

buf += bytes([0]) * padding
encd = aes.encrypt(buf)
print("sleeping")
input("enter something to turn off lights again: ")
print("sending again")
hexdump(buf)
sock.send(encd)

sock.close()