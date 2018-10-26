import socket
import struct 
import array
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

sock.connect(('localhost', 13371))


fmt  = "!3si"

buf = bytearray(struct.calcsize(fmt))

struct.pack_into(fmt,buf,0,'cus'.encode('UTF-8'),2)
pubkey = sock.recv(550)

print("Recieved key")

pubk = RSA.import_key(pubkey)

enctor = PKCS1_v1_5.new(pubk)


encd = enctor.encrypt(buf)

print(pubkey[:10])

print("Sending %s bytes: %s..."%(len(encd), encd[:10]))

sock.send(encd)