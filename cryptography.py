"""
Cryptography Module - Adam Christensen
2021/02/19
Using the cryptodome library
"""
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

HASHNUM = 10


def _hash(str):
    """
    hash
        SHA=256 hash function
    :param
        str: the python string to be hashed
    :return
        returns a 62 digit python string representing the 32 byte hash
    """
    hash_object = SHA256.new(data=bytes(str, 'utf-8'))
    hexstring = hash_object.hexdigest()
    return hexstring


def pwd2hash(str):
    """
    pwd2hash
        creates a hash from the password by running SHA256 multiple times
    :param
        str: the password. a python string.
    :return
        returns a 64 digit python string. this is the hash stored in the database
    """
    for i in range(HASHNUM + 1):
        str = _hash(str)
    return str


def pwd2key(str):
    """
    pwd2hash
        creates a AES password from the users password
    :param
        str: the password. type: string.
    :return
        returns a 32 digit python string. this is the AES password
    """
    for i in range(HASHNUM):
        str = _hash(str)
    return str[0:32]


def encrypt_mssg(mssg, key):
    """
    encrypt_mssg
        creates cipher text, tag, and a nonce using AES
        tag and nonce can be public
    :param
        mssg: the message to be encrypted. type: string.
        key: the key be used in the cipher. type: string
    :return
        returns a 'utf-8' encoded cipher text. type: bytes
    """
    cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(bytes(mssg, 'utf-8'))
    nonce = cipher.nonce
    return ciphertext, tag, nonce


def decrypt_mssg(mssg, key, tag, nonce):
    """
    encrypt_mssg
        decrypts AES encrypted cipher text into plain text
    :param
        mssg: the message to be decrypted. type: bytes.
        key: the key be used in the cipher. type: string
        tag: AES tag. type: bytes
        nonce: AES nonce. type: bytes
    :return
        returns plain text of the encoded message. type: string
    """
    cipher = AES.new(bytes(key, 'utf-8'), AES.MODE_EAX, nonce)
    ciphertext = cipher.decrypt_and_verify(mssg, tag)
    return ciphertext.decode('utf-8')


def create_gp():
    raise NotImplementedError