"""
Main
2021/02/26

NOTE: A lot of these functions and classes will probably be moved to the network/GUI module
NOTE: the cryptography module uses byte strings (e.g. b'this is a byte') and database might also.
NOTE: what is not included in this code/skeleton is how to verify if a message has been received
"""
import cryptography as c
import database as d

import socket
import threading
import sys
import traceback
import pickle

from requests import get

import flask
import main
from flask import request


USER_ID = 0        # Every user on the local system will have their own ID.
CONTACT_LIST = []  # [[ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey, Port#],...]
MESSAGE_LIST = []  # [[[UserID, ContactID, MessageID, IV, Text, Timestamp, Sent],...], ...] something like this?
DB_KEY = None      # key used for encrypting and decrypting entries in the database
PUBLIC_KEY = None  # Users public key
PRIVATE_KEY = None # Users private key
DIFFIE_HELLMAN = None  # diffie hellman object. see cryptography.py

def initialize_database(db_name: str):
    try:
        db_file = open(db_name, "r")
        db_file.close()
        print("database " + db_name + " already exists")
        return d.database(db_name)
    except:
        db = d.database(db_name)
        db.create_users()
        print("created users table")
        db.create_contacts()
        print("created contacts table")
        db.create_messages()
        print("created messages table")
        return db

DATABASE = initialize_database("Primary") # not sure how the database is going to be handled



# networking constants

BUFSIZE = 4096
FORMAT = 'utf-8'  # probably not needed
SERVER_IP = socket.gethostbyname(socket.gethostname())
PORT = 5550


class Message:
    def __init__(self, user_id, machine_id, flag, message, signature=None, tag=None, nonce=None):
        self.user_ID = user_id  # the user's ID on the user's system
        self.machine_ID = machine_id  # the ID of the contact on the contact's system (different from contactID)
        self.flag = flag  # flag to help process the message
        self.message = message  # the message
        self.signature = signature  # cryptographic signature
        self.tag = tag  # needed for decrypting the message (should not be encrypted)
        self.nonce = nonce  # needed for decrypting the message (should not be encrypted)

def get_user_ip() -> str:
    public_ip = get("http://ipgrab.io").text
    # print("public ip: ", public_ip)
    return public_ip[:(len(public_ip)-1)]

# NOTE: TODO need to add port number
def encode_friend(ip_address, user_id):
    ip_address = ip_address.split('.')
    ip_address = list(map(int, ip_address))
    a = 8
    friendcode = []
    for i in ip_address:
        friendcode.append(i << a)
        a += 8
    friendcode = sum(friendcode)
    friendcode += user_id
    friendcode = hex(friendcode)
    friendcode = friendcode[2:]
    return friendcode

# NOTE: TODO need to add port number
def decode_friend(friendcode):
    friendcode = int(friendcode, 16)
    ip_address = []
    while friendcode != 0:
        ip_address.append(friendcode & 255)
        friendcode = friendcode >> 8
    machine_id = ip_address.pop(0)
    print(ip_address)
    ip_address = '.'.join(map(str, ip_address))
    return machine_id, ip_address

# TODO Will need updating with friendcode that takes port
def create_account(username: str, password: str):

    print("Creating account...")
    # check if username is unique
    unique = DATABASE.find_user(username)
    DATABASE.close()

    if unique:
        # this may have to be reworked to include the flask functionality
        # of displaying a specific page or error message upon receiving
        # an invalid/in-use username
        print("User already exists")
        return None

    # (optional) check if password is secure (just check length?)
    # TODO IF WE HAVE TIME

    # create public and private key
    PublicKey, PrivateKey = c.generate_public_private()

    # generate hash of user's password
    PasswordHash = c.pwd2hash(c.string2bytes(password))

    # user's local encryption key, not stored as global
    # variable yet, this will be done during login
    db_key = c.pwd2key(c.string2bytes(password))

    # generate initialization vector for this user
    User_IV = c.create_iv()

    # get public ip address (must be connected to internet, otherwise blank)
    IP_address = get_user_ip()

    # encrypt publicKey, privateKey
    enc_PublicKey = c.encrypt_db(PublicKey, db_key, User_IV)
    enc_PrivateKey = c.encrypt_db(PrivateKey, db_key, User_IV)
    enc_PORT = c.encrypt_db(c.string2bytes(str(PORT)), db_key, User_IV)
    enc_IP_address = c.encrypt_db(c.string2bytes(IP_address), db_key, User_IV)

    # anything which is initially stored as bytes must be encoded
    # as a base64 byte string and converted to a python string before
    # being added to the database
    UserID = DATABASE.new_user(username,
                               c.bytes2string(c.bytes2base64(PasswordHash)),
                               c.bytes2string(c.bytes2base64(User_IV)),
                               c.bytes2string(c.bytes2base64(enc_IP_address)),
                               c.bytes2string(c.bytes2base64(enc_PORT)),
                               c.bytes2string(c.bytes2base64(enc_PublicKey)),
                               c.bytes2string(c.bytes2base64(enc_PrivateKey)))
    DATABASE.close()

    print(f"New user {username} created! "
          f"UserID: {UserID}")

    # global variables will need to be set in login, but this may change
    # when we figure out how to make flask and sql play nice
    return True


# contact in CONTACT_LIST [ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey]
def login(username, password):

    # Step 0: find if user with given username exists in the system
    user_info = DATABASE.find_user(username)
    if user_info:
        user_info = user_info[0]
        print(f"User {user_info[1]} found!")
        PasswordHash = c.base642bytes(c.string2bytes(user_info[2]))
    else:
        # database will return empty list if user not found
        print("User not found")
        return None

    global DB_KEY
    # Step 1: Authenticate User
    password_hash = c.pwd2hash(c.string2bytes(password))

    # Step 1a: check if password's hash matches stored hash
    print(password_hash)
    print(PasswordHash)
    if (password_hash == PasswordHash):
        print("Password was correct!")
        # if the correct password is entered
        DB_KEY = c.pwd2key(c.string2bytes(password))
        UserID = int(user_info[0])
        User_IV = c.base642bytes(c.string2bytes(user_info[3]))
        IP_Adress = c.base642bytes(c.string2bytes(user_info[4]))
        User_PORT = c.base642bytes(c.string2bytes(user_info[5]))
        PublicKey = c.base642bytes(c.string2bytes(user_info[6]))
        PrivateKey = c.base642bytes(c.string2bytes(user_info[7]))
    else:
        print("Incorrect password")
        # if the wrong password is entered
        return None

    # Step 2 (if step 1 is a success): set global variables: UserID, PUBLIC_KEY, PRIVATE_KEY from what database returned
    global USER_ID, PUBLIC_KEY, PRIVATE_KEY
    USER_ID = UserID
    PUBLIC_KEY = c.decrypt_db(PublicKey, DB_KEY, User_IV)
    PRIVATE_KEY = c.decrypt_db(PrivateKey, DB_KEY, User_IV)

    # Step 3: Create Contact List
    #TODO DATABASE: return all contacts of a specific User as a nested list (You'll need to JOIN USERS and CONTACTS)

    # this should decrypt the necessary values returned by the database
    for contact in CONTACT_LIST:
        i = 2
        while i != 5:
            contact[i] = c.decrypt_db(contact[i], DB_KEY, contact[1])
    # Step 4: Pull most recent messages of each user
    # TODO DATABASE: create a function that returns the n most recent messages between a user and a contact
    # loop through the contact list and run the database function to pull the appropriate messages from the database
    #  use decipher_message_list()
    return NotImplementedError

def add_contact(ip_address, port, Contactname, public_key=None):
    # I haven't gotten to this yet, but I'm assuming that this will
    # actually need to store a contact in the database rather than
    # updating the global contact list variable.
    # I may be wrong, but we'll probably need a helper function
    # for updating the local contact list whenever a new user logs in
    # and we can leave this to be database insertion

    new_contact = []

    # Create a contactID
    if len(CONTACT_LIST) == 0:
        # first contact
        ContactID = 1
    else:
        ContactID = CONTACT_LIST[-1][0] + 1

    # create new contact
    new_contact.append(ContactID)
    new_contact.append(c.create_iv())
    new_contact.append(0)
    new_contact.append(Contactname)
    new_contact.append(ip_address)
    new_contact.append("placeholder secret key")
    new_contact.append(public_key)
    new_contact.append(port)

    # add contact to CONTACT_LIST
    CONTACT_LIST.append(new_contact)

    #print(CONTACT_LIST)

    return True

def start_keyexchange(contact):
    # create the initial message
    message = Message(USER_ID, contact[2], 'a1', PUBLIC_KEY, None)

    # send the message
    send_message(message, contact)


# contact in CONTACT_LIST [ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey]
def receive_message(connection, address):
    # Step 1: check if message.contact_ID == USER_ID i.e check if message is intended for the current user
    #  we may have to send an error message back to the sender
    # Step 2: find contact in CONTACT_LIST based on ip_address and machineID
    # Step 3: process the message

    global DIFFIE_HELLMAN

    print("you have received a message from: ", address)

    # NETWORK
    # get the sent message object
    # TODO: larger messages might require the recieving to be done in a loop
    msg = connection.recv(BUFSIZE)
    message = pickle.loads(msg)

    # close the connection
    connection.close()

    if message.flag == 'm':
        print("text received!")
        print(message)
        print(message.message)

    # TODO test this encryption
    # decrypt message
        # create secret key from contact
        # plaintext = c.decrypt_mssg(message.message, secret_key, message.tag, message.nonce)
    # encrypt message for the database
        # iv = c.create_iv()
        # ciphertext = c.encrypt_db(plaintext, DB_KEY, iv)
        # TODO DATABASE: create a new message

        # Add the new message to MESSAGE_LIST and update the GUI if appropriate
        return True

    # Below are automatic key exchange protocol messages. These messages should not be kept in the database
    elif message.flag == 'a1':
        print("flag: a1")
        # flag a1: step 1 of the public key exchange
        public_key = message.message
        machineID = message.user_ID

        # update contact in CONTACT_LIST with public_key
        for item in CONTACT_LIST:
            # find the contact with this ip address 
            if item[4] == address[0]:
                # update public key
                item[6] = public_key

                # create message object
                new_message = Message(USER_ID, machineID, 'a2', PUBLIC_KEY)

                # NETWORKING: send this message
                send_message(new_message, item)

        return True

    elif message.flag == 'a2':
        print("flag: a2")
        # flag a2: step 2 of the public key exchange
        machineID = message.user_ID
        public_key = message.message

        # add public_key to contact in CONTACT_LIST
        for item in CONTACT_LIST:
            # find the contact with this ip address
            if item[4] == address[0]:
                # update public key
                item[6] = public_key

                # initiate diffie hellman key exchange
                DIFFIE_HELLMAN = c.DiffieHellman()
                g, p = DIFFIE_HELLMAN.create_gp()
                value = DIFFIE_HELLMAN.create_value()
                #print("g: ", g)
                #print("p: ", p)
                #print("value: ", value)
                new_message = Message(USER_ID, machineID, 'b1', (g, p, value))

                # NETWORKING: send this message
                send_message(new_message, item)

        return True

    elif message.flag == 'b1':
        print("flag: b1")
        # flag b1: step 1 of the diffie hellman key exchange
        machineID = message.user_ID
        g, p, value = message.message
        DIFFIE_HELLMAN = c.DiffieHellman(g, p)
        value = DIFFIE_HELLMAN.create_value()
        #print("g: ", g)
        #print("p: ", p)
        #print("value: ", value)
        key = DIFFIE_HELLMAN.create_key(value)

        # add key to contact in CONTACT_LIST - this completes the contact
        for item in CONTACT_LIST:
            # find the contact with this ip address
            if item[4] == address[0]:
                # update key
                item[5] = key

                print(item)

                #TODO DATABASE add new contact

                # NETWORKING: send this message
                new_message = Message(USER_ID, machineID, 'b2', value)
                send_message(new_message, item)

        return True

    elif message.flag == 'b2':
        print("flag: b2")
        value = message.message
        key = DIFFIE_HELLMAN.create_key(value)

        # add key to contact in CONTACT_LIST - this completes the contact
        for item in CONTACT_LIST:
            # find the contact with this ip address
            if item[4] == address[0]:
                # update key
                item[5] = key

                print(item)
        
                #TODO DATABASE add new contact

        return True

    else:
        print("Message Flag Error")
        return False

def create_message(text, contact):
    # get necessary info
    ip_address = contact[4]
    machineID = contact[2]
    secret_key = contact[5]
    # create message
    ciphertext, tag, nonce = c.encrypt_mssg(text, secret_key)
    signature = c.create_signature(text, PRIVATE_KEY)
    message = Message(USER_ID, machineID, 'm', ciphertext, signature, tag, nonce)


# contact in CONTACT_LIST [ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey]
def send_message(message, contact):
    # get necessary info
    ip_address = contact[4]
    port = contact[7]

    # create a socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip_address, port))

    # pickle the message object and send it
    pickled_message = pickle.dumps(message)
    client.send(pickled_message)

    # close the connection
    client.close()

    # TODO NETWORK: if message is successfully sent, update database, MESSAGE_LIST, and GUI if appropriate


# [[UserID, ContactID, MessageID, IV, Text, Timestamp, Sent],...]
def decipher_message_list(messages):
    for message in messages:
        message[4] = c.decrypt_db(message[4], DB_KEY, message[3])
        message[5] = c.decrypt_db(message[5], DB_KEY, message[3])
        message[6] = c.decrypt_db(message[6], DB_KEY, message[3])
    # may need to order the messages by their timestamp
    # may also want to remove unnecessary information (UserID, ContactID, IV)
    return messages

def start_server():
    """
    The purpose of this function is to
    (a) create a server socket
    (b) listen for connections
    (c) handle incoming messages
    """

    # create a socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        server.bind((SERVER_IP, PORT))
    except:
        print("Bind failed. Error : " + str(sys.exc_info()))
        sys.exit()

    # listen
    server.listen()
    print('server now listening at: ', SERVER_IP, PORT)

    # continuously loop to accept connections
    while True:
        # accept a connection
        connection, address = server.accept()
        ip, port = server.getsockname()
        print("Connected with " + ip + ":" + str(port))

        # start a new thread for connection
        try:
            thread = threading.Thread(target=receive_message, args=[connection, address])
            thread.start()
        except:
            print('thread did not start')
            traceback.print_exc()


if __name__ == "__main__":
    # start the message server
    start_server()
