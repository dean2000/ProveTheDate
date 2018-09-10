import socket
import hashlib
import struct

data = open('data', 'rb').read()
hashed_data = hashlib.sha3_256(data).digest()

with socket.socket() as sock:
    sock.connect(('localhost', 1337))
    
    sock.sendall(hashed_data)
    print('Data sent.')

    date = sock.recv(10)
    sig = sock.recv(64)
    sig_filename = 'signature-{}'.format(date.decode())
    open(sig_filename, 'wb').write(sig)
    print('Sucess!!')