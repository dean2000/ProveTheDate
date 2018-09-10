import socket
import hashlib
import struct
from ecdsa import VerifyingKey

data = open('data', 'rb').read()
sig = open('signature', 'rb').read()

def get_pub(sock):
    sock.send(b'\x01')
    length, = struct.unpack('>I', sock.recv(4))
    return sock.recv(length)

with socket.socket() as sock:
    sock.connect(('localhost', 1337))

    # get public key
    pubkey = get_pub(sock)
    key = VerifyingKey.from_der(pubkey)

    hash = hashlib.sha3_512(data).digest()
    key.verify()