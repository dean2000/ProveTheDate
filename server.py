import socketserver
import datetime
from ecdsa import SigningKey, VerifyingKey, SECP256k1
import os, glob
import hashlib

class KeyHolder:
    self.SIZE_OF_HASH = hashlib.sha3_512().digest_size
    self.SIZE_OF_SIG = 64

    def __init__(self):
        if not os.path.isdir('keys'):
            os.mkdir('keys')

    def sign(self, data):
        return self._get_key().sign(data)

    # TODO: Delete this functionality after keeping the public keys in other server
    def verify(self, data, signature):
        return self._get_key().get_verifying_key().verify(signature, data)

    def get_public_key(self):
        return self._get_key().get_verifying_key().to_pem()

    def _get_key(self):
        today = datetime.datetime.now().date().isoformat()
        if not os.path.isfile(f'keys/publickey-{today}.pem'):
            return self._generate_keypair(today)
        else:
            key_pem = open(f'keys/privatekey-{today}.pem', 'rb').read()
            return SigningKey.from_pem(key_pem)
        

    def _generate_keypair(self, today):
        # remove all private keys
        for filename in glob.glob('keys/privatekey-*.pem'):
            os.remove(filename)

        # generate key and save it on disk
        key = SigningKey.generate(curve=SECP256k1)
        with open(f'keys/privatekey-{today}.pem', 'wb') as privkey:
            privkey.write(key.to_pem())
        with open(f'keys/publickey-{today}.pem', 'wb') as pubkey:
            pubkey.write(key.get_verifying_key().to_pem())
        return key

keyholder = None

class MyTCPHandler(socketserver.BaseRequestHandler):
    """
    It is instantiated once per connection to the server
    """
    def handle(self):
        operation, result = self.request.recv(1), b''

        if operation == b'\x00':
            # sign
            data = self.request.recv(keyholder.SIZE_OF_HASH) # sha-3 512 hash of the data (only for efficiency).
            result = keyholder.sign(data) 
        elif operation == b'\x01':
            # get public key of today
            result = keyholder.get_public_key()
        elif operation == b'\x02':
            # verify (should be done by the web server (which holds all the public keys), not by the crypto server!)
            data = self.request.recv(keyholder.SIZE_OF_HASH)
            signature = self.request.recv(keyholder.SIZE_OF_SIG)
            result = keyholder.verify(data, signature)
        
        self.request.sendall(result)

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