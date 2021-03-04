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

USER_ID = 0        # Every user on the local system will have their own ID.
CONTACT_LIST = []  # [[ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey],...]
MESSAGE_LIST = []  # [[[UserID, ContactID, MessageID, IV, Text, Timestamp, Sent],...], ...] something like this?
DB_KEY = None      # key used for encrypting and decrypting entries in the database
PUBLIC_KEY = None  # Users public key
PRIVATE_KEY = None # Users private key
DIFFIE_HELLMAN = None  # diffie hellman object. see cryptography.py
# DATABASE = None  # not sure how the database is going to be handled

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


def create_account(username, password):
    # check if username is unique.
    # (optional) check if password is secure (just check length?)
    # create public and private key
    PUBLIC_KEY, PRIVATE_KEY = c.generate_public_private()

    # get my public ip address
    public_ip = get("http://ipgrab.io").text
    # create friendcode
    friendcode = encode_friend(public_ip, USER_ID)
    # encrypt friendcode, publicKey, privateKey

    print("PUBLIC_KEY: ", PUBLIC_KEY)
    print("PRIVATE_KEY: ", PRIVATE_KEY)
    print("friendcode: ", friendcode)
    # hash the password
    # TODO DATABASE: create a new user and return the UserID
    # set the global variables. could probably be done by running login()
    return True


# contact in CONTACT_LIST [ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey]
def login(username, password):
    global DB_KEY
    # Step 1: Authenticate User
    password_hash = c.pwd2hash(password)
    #TODO DATABASE: find user based on username and return all of the user's data in a list or tuple
    if (password_hash == PasswordHash):
        # if the correct password is entered
        DB_KEY = c.pwd2key(c.string2bytes(password))
    else:
        pass
        # if the wrong password is entered
    # Step 2 (if step 1 is a success): set global variables: UserID, PUBLIC_KEY, PRIVATE_KEY from what database returned
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


# contact in CONTACT_LIST [ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey]
def add_contact(friendcode, public_key=None):
    # NOTE: there could be issues if both users add a contact at the same time
    # Initiate creating a new contact
    new_contact = []

    # Create a contactID
    if len(CONTACT_LIST) == 0:
        # first contact
        ContactID = 1
    else:
        ContactID = CONTACT_LIST[-1][0] + 1
    # Get MachineID and IP_address from friendcode
    MachineID, IP_address = decode_friend(friendcode)

    # create new contact
    new_contact.append(ContactID)
    new_contact.append(c.create_iv())
    new_contact.append(MachineID)
    new_contact.append("placeholder name")
    new_contact.append(IP_address)
    new_contact.append("placeholder secret key")
    new_contact.append("placeholder public key")

    # Need to handle Contactname somehow. Either let the user enter it in, or have the contact send that info.
    # add new Contact in CONTACT_LIST (contact will be incomplete as we don't have SecretKey or PublicKey
    CONTACT_LIST.append(new_contact)
    # I don't think it's worth adding this new contact to the database until the key exchange process is complete
    # Initiate key exchange by sending the message below. SecretKey and PublicKey will be created in receive_message()
    message = Message(USER_ID, machineID, 'a1', PUBLIC_KEY, None)

    #TODO NETWORKING: send this message
    send_message(message, new_contact)

    return True


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

        # flag a1: step 1 of the public key exchange
        public_key = message.message
        machineID = message.user_ID

        # someone has added us as a contact. 
        # we need to add them to our contact list

        # generate friendcode 
        friendcode = encode_friend(address[0], machineID)

        # add contact
        add_contact(friendcode, public_key, 1)

        # create message object
        new_message = Message(USER_ID, machineID, 'a2', PUBLIC_KEY)

        # NETWORKING: send this message
        send_message(new_message, CONTACT_LIST[-1])

        return True

    elif message.flag == 'a2':
        # flag a2: step 2 of the public key exchange
        machineID = message.user_ID
        public_key = message.message

        # add public_key to contact in CONTACT_LIST
        CONTACT_LIST[-1][6] = public_key

        # initiate diffie hellman key exchange

        DIFFIE_HELLMAN = c.DiffieHellman()
        g, p = DIFFIE_HELLMAN.create_gp()
        value = DIFFIE_HELLMAN.create_value()
        new_message = Message(USER_ID, machineID, 'a', (g, p, value))

        # TODO NETWORKING: send this message
        send_message(new_message, CONTACT_LIST[-1])

        return True

    elif message.flag == 'b1':
        # flag b1: step 1 of the diffie hellman key exchange
        machineID = message.user_ID
        g, p, value = message.message
        DIFFIE_HELLMAN = c.DiffieHellman(g, p)
        value = DIFFIE_HELLMAN.create_value()
        key = DIFFIE_HELLMAN.create_key(value)
        # add key to contact in CONTACT_LIST - this completes the contact
        CONTACT_LIST[-1][5] = key
        #TODO DATABASE add new contact

        new_message = Message(USER_ID, machineID, 'b2', value)
        # TODO NETWORKING: send this message
        send_message(new_message, CONTACT_LIST[-1])
        return True

    elif message.flag == 'b2':
        value = message.message
        key = DIFFIE_HELLMAN.create_key(value)
        # add key to contact in CONTACT_LIST - this completes the contact
        CONTACT_LIST[-1][5] = key
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

    # create a socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((ip_address, PORT))

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