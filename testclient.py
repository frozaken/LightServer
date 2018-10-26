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

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect(('localhost', 13371))


fmt  = "!3si"

buf = bytearray(struct.calcsize(fmt))

struct.pack_into(fmt,buf,0,'cus'.encode('UTF-8'),2)

privkey = peer_public_key = ec.generate_private_key(
    ec.SECP384R1(), 
    default_backend()
)

servpubkeybytes = sock.recv(120)

sock.send(
    privkey.public_key().public_bytes(
        serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
)

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

print("Derived key: %s"%derived[:10])
encd = IV + aes.encrypt(buf)

print(IV)

print("Sending %s bytes: %s..."%(len(encd), encd[:10]))

sock.send(encd)