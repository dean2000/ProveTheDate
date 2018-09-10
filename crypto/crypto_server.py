import socketserver
import datetime
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import os
import hashlib

"""
Server is only signing keys.
If there is not key on the disk (first running), the server generates the key pair, and the public key should be published.

The protocol is as follows:
1. client sends hash(data) where hash function is sha3_256
2. server signs (hash(data) || today) and sends that to the user. today must be fixed length format
"""

class KeyHolder:
    SIZE_OF_HASH = hashlib.sha3_256().digest_size

    def __init__(self):
        if not os.path.isfile(f'privatekey.pem'):
            print('"privatekey.pem" is not present!')
            self._generate_keypair()

        key_pem = open(f'privatekey.pem', 'rb').read()
        self.key = SigningKey.from_pem(key_pem)

    def sign(self, data):
        return self.key.sign(data, hashfunc=hashlib.sha3_256)

    def _generate_keypair(self):
        # generate key and save it on disk
        key = SigningKey.generate(curve=SECP256k1)
        with open(f'privatekey.pem', 'wb') as privkey:
            privkey.write(key.to_pem())
        with open(f'publickey.pem', 'wb') as pubkey:
            pubkey.write(key.get_verifying_key().to_pem())
        print(f'New keypair generated, public key:\n{key.get_verifying_key().to_pem().decode()}')

keyholder = None

class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    It is instantiated once per connection to the server
    """
    def handle(self):
        # sign
        today = datetime.date.today().isoformat().encode()

        data = self.request.recv(keyholder.SIZE_OF_HASH) # sha-3 512 hash of the data (only for efficiency).
        data += today # add the date
        print(f'Signing data: {data}')

        # send the date and signed data back to client
        self.request.sendall(today)
        self.request.sendall(keyholder.sign(data))
        

import sys
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f'Usage: python3 {sys.argv[0]} <port>', file=sys.stderr)
        exit(1)

    HOST, PORT = 'localhost', int(sys.argv[1])

    keyholder = KeyHolder()

    # Create the server
    server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)

    # Activate the server
    server.serve_forever()