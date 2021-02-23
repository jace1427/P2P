"""
Cryptography Module - Adam Christensen
2021/02/22
Using the cryptodome library
"""
import cryptonumbers as cn
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15

HASHNUM = 100


def string2bytes(string):
    return bytes(string, 'utf-8')


def bytes2string(_bytes):
    _bytes.decode('utf-8')


def _hash(byte_str):
    """
    hash
        SHA=256 hash function
    :param
        byte_str: the python string to be hashed. type: bytes
    :return
        returns a 62 digit python string representing the 32 byte hash
    """
    hash_object = SHA256.new(byte_str)
    hash_bytes = hash_object.digest()
    return hash_bytes


def pwd2hash(string):
    """
    pwd2hash
        creates a hash from the password by running SHA256 multiple times
    :param
        string: the password. type: bytes
    :return
        returns a hash. this is the hash stored in the database. type: bytes
    """
    for i in range(HASHNUM + 1):
        string = _hash(string)
    return string


def pwd2key(string):
    """
    pwd2hash
        creates a AES password from the users password
    :param
        string: the password. type: type: bytes
    :return
        returns a key. this is the AES password. type: bytes
    """
    for i in range(HASHNUM):
        string = _hash(string)
    return string[:24]


def create_iv():
    return get_random_bytes(8)


def encrypt_db(mssg, key, iv):
    """
    encrypt_mssg
        creates cipher text, tag, and a nonce using triple DES
        tag and nonce can be public
    :param
        mssg: the message to be encrypted. type: bytes
        key: the key be used in the cipher. type: bytes
        iv: the initialization vector: type: bytes
    :return
        returns a 'utf-8' encoded cipher text. type: bytes
    """
    cipher = DES3.new(key, DES3.MODE_CFB, iv)
    ciphertext = cipher.encrypt(mssg)
    return ciphertext


def decrypt_db(mssg, key, iv):
    """
    encrypt_mssg
        decrypts AES encrypted cipher text into plain text
    :param
        mssg: the message to be decrypted. type: bytes.
        key: the key be used in the cipher. type: bytes
        iv: the initialization vector: type: bytes
    :return
        returns plain text of the encoded message. type: bytes
    """
    cipher = DES3.new(key, DES3.MODE_CFB, iv)
    plaintext = cipher.decrypt(mssg)
    return plaintext


class DiffieHellman:
    """
    class used for Diffie Hellman key exchange
    """
    def __init__(self, generator=None, prime=None):
        self.generator = generator
        self.prime = prime
        self.private = 0x0
        self.value = 0x0
        self.key = b''

    def create_gp(self):
        self.generator = cn.generator
        self.prime = cn.prime5
        return self.generator, self.prime

    def create_value(self, length=600):
        random_bytes = get_random_bytes(length)
        random_int = int.from_bytes(random_bytes, byteorder='big')
        self.private = random_int
        self.value = pow(self.generator, self.private, self.prime)
        return self.value

    def create_key(self, value):
        secret = pow(value, self.private, self.prime)
        secret = secret.to_bytes(secret.bit_length() // 8 + 1, byteorder='big')
        _bytes = bytes(secret)
        key = _hash(_bytes)
        self.key = key[0:32]
        return self.key


def encrypt_mssg(mssg, key):
    """
    encrypt_mssg
        creates cipher text, tag, and a nonce using AES
        tag and nonce can be public
    :param
        mssg: the message to be encrypted. type: bytes
        key: the key be used in the cipher. type: bytes
    :return
        returns cipher text. type: bytes
    """
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(mssg)
    nonce = cipher.nonce
    return ciphertext, tag, nonce


def decrypt_mssg(mssg, key, tag, nonce):
    """
    encrypt_mssg
        decrypts AES encrypted cipher text into plain text
    :param
        mssg: the message to be decrypted. type: bytes.
        key: the key be used in the cipher. type: bytes
        tag: AES tag. type: bytes
        nonce: AES nonce. type: bytes
    :return
        returns decrypted message. type: bytes
    """
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    ciphertext = cipher.decrypt_and_verify(mssg, tag)
    return ciphertext


def generate_public_private():
    """
    generate_public_private
        generates RSA public and private key
    :return
        returns public and private key. type: bytes
    """
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return public_key, private_key


def encrypt_rsa(mssg, key):
    """
    encrypt_rsa
        encrypts plaintext into ciphertext using RSA encryption
    :param
        mssg: the message to be encrypted. type: bytes
        key: the key be used in the cipher. type: bytes
    :return
        returns encrypted message. type: bytes
    """
    rsa_key = RSA.importKey(key)
    cipher = PKCS1_OAEP.new(rsa_key)
    ciphertext = cipher.encrypt(mssg)
    return ciphertext


def decrypt_rsa(mssg, key):
    """
    decrypt_mssg
        decrypts RSA encrypted ciphertext into plaintext
    :param
        mssg: the message to be decrypted. type: bytes.
        key: the key be used in the cipher. type: bytes
    :return
        returns decrypted message. type: bytes
    """
    rsa_key = RSA.importKey(key)
    cipher = PKCS1_OAEP.new(rsa_key)
    plaintext = cipher.decrypt(mssg)
    return plaintext


def create_signature(mssg, key):
    """
    create_signature
        creates a signature from a private key and a message
    :param
        mssg: the message to be decrypted. type: bytes.
        key: the key be used in the cipher. type: bytes
    :return
        returns a signature. type: bytes
    """
    rsa_key = RSA.importKey(key)
    h = SHA256.new(mssg)
    signature = pkcs1_15.new(rsa_key).sign(h)
    return signature


def check_signature(mssg, signature, key):
    """
    check_signature
        checks a signature using a public key and a message
    :param
        mssg: the message the signature should contain. type: bytes.
        signature: the signature to be checked. type bytes
        key: the key be used in the cipher. type: bytes
    :return
        returns a signature. type: bytes
    """
    h = SHA256.new(mssg)
    rsa_key = RSA.importKey(key)
    try:
        pkcs1_15.new(rsa_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

