import socket
import hashlib
import struct
from ecdsa import VerifyingKey, BadSignatureError

def verify(data_filename, signature_filename):
    data = open(data_filename, 'rb').read()
    sig = open(signature_filename, 'rb').read()

    data = hashlib.sha3_256(data).digest() + signature_filename[-10:].encode()

    # public key
    pubkey_pem = open('publickey.pem', 'rb').read()
    key = VerifyingKey.from_pem(pubkey_pem)

    try:
        key.verify(sig, data, hashfunc=hashlib.sha3_256)
        print('Correct!')
    except BadSignatureError:
        print('Incorrect!')

import sys
def main(argv):
    if len(argv) < 3:
        print(f'Usage: {argv[0]} <data> <signature>', file=sys.stderr)
    
    verify(argv[1], argv[2])

if __name__ == '__main__':
    main(sys.argv)