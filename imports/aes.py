import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES
import random


class AESCipher:
    def __init__(self, key):
        self.key = hashlib.sha256(str(key).encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        # # create an AES cipher with the key and IV
        cipher = AES.new(self.key, AES.MODE_ECB)
        # # encode the encrypted raw data and return
        return cipher.encrypt(raw)

    def decrypt(self, msg):
        # create a new cipher for the given pair of key and iv
        decipher = AES.new(self.key, AES.MODE_ECB)
        # decrypt the encrypted data
        plain = decipher.decrypt(msg)
        # unpad the plain text to its original form
        return self._unpad(plain)

    def _pad(self, string):
        try:
            x = len(string) % AES.block_size
            pad = AES.block_size - x
            random_pad = bytes(random.sample(range(255), pad-1))
            string += random_pad + bytes([pad])
            return string
        except Exception as e:
            print(f"Error in AES : {e}")
            pass

    @staticmethod
    def _unpad(string):
        return string[:-string[-1]]
