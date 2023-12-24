from Crypto.Cipher import ChaCha20
from Crypto.Hash import SHA3_256
from os import urandom
from random import random

ENCODING = 'utf-8'

N_KEYS = 8

_SALT_FILE = open('salt.dat', 'rb')
SALTS = [_SALT_FILE.read(256) for _ in range(N_KEYS)]

class CipherGenerator:
    def __init__(self, password):
        self.keys = self.gen_keys(password)

    @classmethod
    def gen_keys(cls, pwd: str) -> [bytes]:
        keys = []
        for salt in SALTS:
            hasher = SHA3_256.new(pwd.encode(ENCODING) + salt)
            for _ in range(1000):
                hasher = SHA3_256.new(hasher.digest())
            keys.append(hasher.digest())
        return tuple(keys)
    @classmethod
    def gen_nonce(cls) -> bytes:
        return urandom(12)

    def renew(self, nonce=None):
        if nonce is None:
            nonce = self.gen_nonce()
        return Cipher([ChaCha20.new(key=k, nonce=nonce) for k in self.keys])

class Cipher:
    def __init__(self, ciphers):
        self.ciphers = ciphers
    def encrypt(self, data: bytes) -> bytes:
        for cipher in self.ciphers:
            data = cipher.encrypt(data)
        return data
    def decrypt(self, data: bytes) -> bytes:
        for cipher in self.ciphers:
            data = cipher.decrypt(data)
        return data


