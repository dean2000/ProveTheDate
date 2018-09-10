import socket
import hashlib
import struct

data = open('data', 'rb').read()

with socket.socket() as sock:
    sock.connect(('localhost', 1337))

    sock.send(b'\x00') # sign
    hash = hashlib.sha3_512(data).digest()
    sock.sendall(hash)

    print('Data sent.')

    sig = sock.recv(64)
    open('signature', 'wb').write(sig)

    print('Sucess!!')