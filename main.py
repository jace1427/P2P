"""
Main
2021/02/26

Authors:
    Adam Christensen
    Riley Matthews
    Justin Spidell
    Evan Podrabsky
    Lannin Nakai
"""

# our modules
import cryptography as c
import database as d

# needed for networking
import socket
import threading
import multiprocessing
import sys
import traceback
import pickle
from requests import get

# general
from datetime import datetime

# Every user on the local system will have their own ID.
USER_ID = 0

# Empty string to represent user
USERNAME = ""

# friendcode of the current user
FRIENDCODE = ""

INTERNAL_FRIENDCODE = ""

# [[ContactID, IV, MachineID, ContactName,
# IP_address, SecretKey, PublicKey, Port#],...]
CONTACT_LIST = []

# [[MessageID, IV, Text, Timestamp, Sent],...]
MESSAGE_LIST = []

# the IV created for the user when they made their account.
# Used for db encryption
USER_IV = None

# key used for encrypting and decrypting entries in the database
DB_KEY = None

# Users public key
PUBLIC_KEY = None

# Users private key
PRIVATE_KEY = None

# diffie hellman object. see cryptography.py
DIFFIE_HELLMAN = None

# user's public ipv4 address
PUBLIC_IP = None

# variable to hold the separate thread running the socket server
SERVER_THREAD = None

# networking constants
BUFSIZE = 4096  # TODO enforce this somewhere
FORMAT = 'utf-8'  # probably not needed

# this reads from config.txt and retrieves the ip address and port to
# use when opening up the socket server
with open("config.txt") as config:
    global SERVER_IP, PORT
    server_ip = config.readline().replace(" ", "")
    server_ip = server_ip[11:(len(server_ip) - 1)]
    port = config.readline().replace(" ", "")
    port = port[5:len(port)]
    if len(server_ip) < 7 or len(server_ip) > 15:
        sys.stderr.write("ERROR: Specified IPV4 address is not valid")
        sys.exit()
    try:
        port = int(port)
        if port < 0 or port > 65535:
            sys.stderr.write("ERROR: Specified port number is not within the"
                             "standardized range")
    except:
        sys.stderr.write("ERROR: Specified port number is not an integer")
        sys.exit()
    SERVER_IP = server_ip
    PORT = port


def initialize_database(db_name: str):
    """
    initialize_database
        Searches for an existing sql database of the given name
        Returns an object of the database if it exists,
        creates a new database if it does not exist

    :param
        db_name: name of the database. type: str

    :return
        database.database: an sql database object from the database module
    """
    try:
        db_file = open(db_name, "r")
        db_file.close()
        return d.database(db_name)
    except:
        db = d.database(db_name)
        db.create_users()
        db.create_contacts()
        db.create_messages()
        return db


# initialize the database global variable
DATABASE = initialize_database("Primary")


class Message:
    def __init__(self, user_id, machine_id, flag, message,
                 signature=None, friendcode=None, tag=None, nonce=None):
        # the user's ID on the user's system
        self.user_ID = user_id

        # the ID of the contact on the contact's system
        # (different from contactID)
        self.machine_ID = machine_id

        # flag to help process the message
        self.flag = flag

        # the message
        self.message = message

        # cryptographic signature
        self.signature = signature

        # friendcode for verifying corresponding
        # contact upon receiving a message
        self.friendcode = friendcode

        # needed for decrypting the message (should not be encrypted)
        self.tag = tag

        # needed for decrypting the message (should not be encrypted)
        self.nonce = nonce


def get_user_ip() -> str:
    """
    get_user_ip
        Queries an ip bot server and returns the user's
        public ipv4 address

    :param
        None

    :return
        public_ipv4: user's public ipv4 address. type: str
    """
    public_ip = get("http://ipgrab.io").text
    return public_ip[:(len(public_ip) - 1)]


def encode_friend(ip_address: str, user_id: int, port: int):
    """
    encode_friend
        encodes a given ip address, user id, and port number
        into one number to be used as the friend code

    :param
        ip_address: the user's public ipv4 address. type: str
        user_id: the number id of the current user. type: int
        port: forwarded port number of the user. type: int

    :return
        friendcode: encoded friendcode. type: str
    """
    ip_address = ip_address.split('.')
    ip_address = list(map(int, ip_address))
    a = 24
    friendcode = []
    for i in ip_address:
        friendcode.append(i << a)
        a += 8
    friendcode = sum(friendcode)
    friendcode += (port << 8)
    friendcode += user_id
    friendcode = hex(friendcode)
    friendcode = friendcode[2:]
    return friendcode


def decode_friend(friendcode):
    """
    decode_friend
        Decodes a friend code into the original ip address,
        user id, and port number

    :param
        friendcode: encoded friendcode to decode. type: str

    :return
        ip_address: decoded ip address. type: str
        user_id: decoded user id. type: int
        port: decoded port number. type: int
    """
    friendcode = int(friendcode, 16)
    ip_address = []
    while friendcode != 0:
        ip_address.append(friendcode & 255)
        friendcode = friendcode >> 8
    machine_id = ip_address.pop(0)
    port = ip_address.pop(0)
    port += ip_address.pop(0) << 8
    ip_address = '.'.join(map(str, ip_address))
    return machine_id, ip_address, port


def create_account(username: str, password: str):
    """
    create_account
        Creates an account in the local sql database with the
        given username and password

    :param
        username: The username of the given user. Not case-sensitive type: str

        password: the password of the given user. Case-sensetive. type: str

    :return
        None
    """

    print("Creating account...")

    if not username or not password:
        return -1
    elif "'" in username or "'" in password:
        return -2
    # check if username is unique
    elif DATABASE.find_user(username.lower()):
        # this may have to be reworked to include the flask functionality
        # of displaying a specific page or error message upon receiving
        # an invalid/in-use username
        print("User already exists")
        return -3

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
    UserID = DATABASE.new_user(username.lower(),
                               c.bytes2string(c.bytes2base64(PasswordHash)),
                               c.bytes2string(c.bytes2base64(User_IV)),
                               c.bytes2string(c.bytes2base64(enc_IP_address)),
                               c.bytes2string(c.bytes2base64(enc_PORT)),
                               c.bytes2string(c.bytes2base64(enc_PublicKey)),
                               c.bytes2string(c.bytes2base64(enc_PrivateKey)))

    print(f"New user {username} created! "
          f"UserID: {UserID}")

    # global variables will need to be set in login, but this may change
    # when we figure out how to make flask and sql play nice
    return 0


# contact in CONTACT_LIST
# [ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey]
def login(username, password):
    """
    login
        This function checks two strings, username and password,
        checks if the credentials match an entry in the user table
        of the database, then prepares the environment for this user
        to move to the messaging GUI by setting global variables from
        the database.
        Socket server is started upon login and stopped when
        exiting the main messaging page

    :param
        username: The username of the given user. Not case-sensitive type: str

        password: the password of the given user. Case-sensetive. type: str

    :return
        None
    """

    global DB_KEY, USER_ID, PUBLIC_KEY, PRIVATE_KEY, \
        USER_IV, CONTACT_LIST, DATABASE, USERNAME, \
        FRIENDCODE, SERVER_THREAD, PUBLIC_IP, SERVER_IP, \
        PORT, INTERNAL_FRIENDCODE

    # no blank username or password accepted
    if not username or not password:
        return -1
    # database doesn't like single apostrophe characters
    elif "'" in username or "'" in password:
        return -2

    # Step 0: find if user with given username exists in the system
    user_info = DATABASE.find_user(username.lower())
    if user_info:
        user_info = user_info[0]
        print(f"User {user_info[1]} found!")
        PasswordHash = c.base642bytes(c.string2bytes(user_info[2]))
        if CONTACT_LIST:
            CONTACT_LIST.clear()
        if MESSAGE_LIST:
            MESSAGE_LIST.clear()
    else:
        # database will return empty list if user not found
        print("User not found")
        return -3

    # Step 1: Authenticate User
    password_hash = c.pwd2hash(c.string2bytes(password))

    # Step 2: check if password's hash matches stored hash
    if (password_hash == PasswordHash):
        # Step 2a (if step 2 is a success): set global variables
        print("Password was correct!")
        # if the correct password is entered, update globals
        DB_KEY = c.pwd2key(c.string2bytes(password))

        USER_ID = int(user_info[0])

        USERNAME = user_info[1]

        USER_IV = c.base642bytes(c.string2bytes(user_info[3]))

        PUBLIC_IP = c.bytes2string(c.decrypt_db(
            c.base642bytes(c.string2bytes(user_info[4])), DB_KEY, USER_IV))

        User_PORT = int(c.bytes2string(c.decrypt_db(
            c.base642bytes(c.string2bytes(user_info[5])), DB_KEY, USER_IV)))

        FRIENDCODE = encode_friend(PUBLIC_IP, USER_ID, User_PORT)

        INTERNAL_FRIENDCODE = encode_friend('127.0.0.1', USER_ID, User_PORT)

        PUBLIC_KEY = c.decrypt_db(
            c.base642bytes(c.string2bytes(user_info[6])), DB_KEY, USER_IV)

        PRIVATE_KEY = c.decrypt_db(
            c.base642bytes(c.string2bytes(user_info[7])), DB_KEY, USER_IV)
    else:
        print("Incorrect password")
        # if the wrong password is entered
        return -4

    # Step 3: Populate Contact List global variable
    _populate_contact_list(USER_ID)

    # Step 4: start server
    SERVER_THREAD = multiprocessing.Process(target=start_server,
                                            args=(USER_ID,
                                                  DB_KEY,
                                                  USER_IV,
                                                  PUBLIC_IP,
                                                  SERVER_IP,
                                                  PORT,
                                                  FRIENDCODE,
                                                  PUBLIC_KEY,
                                                  PRIVATE_KEY))
    return 0


def _clear_contact_list():
    """
    _clear_contact_list
        Helper function to clear contact list
    :param
        None
    :return
        None
    """
    if CONTACT_LIST:
        CONTACT_LIST.clear()


def _clear_message_list():
    """
    _clear_message_list
        Helper function to clear message list
    :param
        None
    :return
        None
    """
    if MESSAGE_LIST:
        MESSAGE_LIST.clear()


def _populate_contact_list(UserID: int) -> None:
    """
    _populate_contact_list
        Helper function for querying the sql database for contacts
        to populate the global CONTACT_LIST

    :param
        UserID: The current user's ID
    :return
        None
    """
    temp_contact_list = DATABASE.find_contacts(UserID)
    for contact in temp_contact_list:
        new_contact = []

        # ContactID (no decrypt)
        new_contact.append(int(contact[1]))

        # Initialization Vector (no decrypt)
        new_contact.append(c.base642bytes(c.string2bytes(contact[2])))

        # Machine ID (decrypt)
        new_contact.append(int(c.bytes2string(c.decrypt_db(c.base642bytes(
            c.string2bytes(contact[3])), DB_KEY, new_contact[1]))))

        # Contact name (decrypt)
        new_contact.append(c.bytes2string(c.decrypt_db(c.base642bytes(
            c.string2bytes(contact[4])), DB_KEY, new_contact[1])))

        # IP address (decrypt)
        new_contact.append(c.bytes2string(c.decrypt_db(c.base642bytes(
            c.string2bytes(contact[5])), DB_KEY, new_contact[1])))

        # Secret key
        new_contact.append(c.decrypt_db(c.base642bytes(
            c.string2bytes(contact[7])), DB_KEY, new_contact[1]))

        # Public key (decrypt)
        new_contact.append(c.decrypt_db(c.base642bytes(
            c.string2bytes(contact[8])), DB_KEY, new_contact[1]))

        # Port (decrypt)
        new_contact.append(int(c.bytes2string(c.decrypt_db(c.base642bytes(
            c.string2bytes(contact[6])), DB_KEY, new_contact[1]))))

        CONTACT_LIST.append(new_contact)

    return


# [[MessageID, IV, Text, Timestamp, Sent],...]
def _populate_message_list(UserID: int, ContactID) -> None:
    """
    _populate_message_list
        Helper function for querying the sql database for messages
        from a specific User and Contact to populate the global MESSAGE_LIST

    :param
        UserID: The current user's ID
    :return
        None
    """
    temp_message_list = DATABASE.find_messages(UserID, ContactID)
    for message in temp_message_list:
        new_message = []

        # MessageID (no decrypt)
        new_message.append(int(message[2]))

        # Initialization Vector (no decrypt)
        new_message.append(c.base642bytes(c.string2bytes(message[3])))

        # Message Text (decrypt)
        new_message.append(c.bytes2string(c.decrypt_db(c.base642bytes(
            c.string2bytes(message[4])), DB_KEY, new_message[1])))

        # Timestamp (decrypt)
        new_message.append(c.bytes2string(c.decrypt_db(c.base642bytes(
            c.string2bytes(message[5])), DB_KEY, new_message[1])))

        # Sent (decrypt)
        # Might be an Int or a string
        new_message.append(int(c.bytes2string(c.decrypt_db(c.base642bytes(
            c.string2bytes(message[6])), DB_KEY, new_message[1]))))

        MESSAGE_LIST.append(new_message)
    return


def add_contact(Contactname, friendcode, public_key=None):
    """
    Creates a new contact in CONTACT_LIST.
    Also adds new contact into database.

    :param
        Contactname: name of contact. type: str
        friendcode: contacts friendcode. type: str
    :return
        returns bool
    """

    # get machineID, port and ip_address from friendcode
    machine_id, ip_address, port = decode_friend(friendcode)

    # temp contactID
    contactID = 0

    # create iv
    contactIV = c.create_iv()

    # create new contact
    new_contact = [contactID, contactIV, machine_id,
                   Contactname, ip_address, "temp sk", public_key, port]

    # insert new contact into CONTACT_LIST
    CONTACT_LIST.append(new_contact)

    # Convert to bytes
    machine_id = c.string2bytes(str(machine_id))
    Contactname = c.string2bytes(str(Contactname))
    ip_address = c.string2bytes(str(ip_address))
    port = c.string2bytes(str(port))
    public_key = c.string2bytes("temp pk")
    sk = c.string2bytes("temp sk")

    # encrypt senstitive information
    enc_machine_id = c.encrypt_db(machine_id, DB_KEY, contactIV)
    enc_Contactname = c.encrypt_db(Contactname, DB_KEY, contactIV)
    enc_ip_address = c.encrypt_db(ip_address, DB_KEY, contactIV)
    enc_port = c.encrypt_db(port, DB_KEY, contactIV)

    # create new contact to be added to database
    new_contact_db = (USER_ID,
                      c.bytes2string(c.bytes2base64(contactIV)),
                      c.bytes2string(c.bytes2base64(enc_machine_id)),
                      c.bytes2string(c.bytes2base64(enc_Contactname)),
                      c.bytes2string(c.bytes2base64(enc_ip_address)),
                      c.bytes2string(c.bytes2base64(enc_port)),
                      c.bytes2string(c.bytes2base64(public_key)),
                      c.bytes2string(c.bytes2base64(sk)))

    # add contact to database
    cid = DATABASE.new_contact(new_contact_db)[0][0]

    # set contactID of new contact to the correct value
    CONTACT_LIST[-1][0] = cid

    return True


def start_keyexchange(contact):
    """
    starts the keyexchange protocols with the given contact

    :param
        contact: list
    :return
        nothing
    """
    # create the initial message
    message = Message(USER_ID, contact[2], 'a1', PUBLIC_KEY,
                      None, friendcode=FRIENDCODE)

    # send the message
    send_message(message, contact)


# contact in CONTACT_LIST
# [ContactID, IV, MachineID, Contactname,
# IP_address, SecretKey, PublicKey, Port#]
def receive_message(connection, address):
    """
    This function handles incoming messages.

    :param
        connection: python socket object
        address: tuple (ip address of sender, port)
    :return
        bool
    """
    global DIFFIE_HELLMAN

    # NETWORK
    # get the sent message object
    # NOTE: larger messages might require the receiving to be done in a loop
    msg = connection.recv(BUFSIZE)
    message = pickle.loads(msg)

    friend = message.friendcode
    useless_machineID, contact_ip, contact_port = decode_friend(friend)

    # get machineID from message
    machineID = message.user_ID

    # close the connection
    connection.close()

    if CONTACT_LIST:
        CONTACT_LIST.clear()
    _populate_contact_list(USER_ID)

    # find contact in CONTACT_LIST based on ip_address and machineID
    index = 0
    for i in range(len(CONTACT_LIST)):
        if (CONTACT_LIST[i][4] == contact_ip) \
                and (CONTACT_LIST[i][2] == machineID) \
                and (CONTACT_LIST[i][7]):
            # found the right contact
            index = i
            break

    # process flags
    if message.flag == 'm':
        print("flag: m, text received!")

        # create secret key from contact
        secret_key = CONTACT_LIST[index][5]

        # decrypt message
        plaintext = c.decrypt_mssg(message.message, secret_key,
                                   message.tag, message.nonce)

        # create message iv
        messageIV = c.create_iv()

        # create timestamp and string representation
        timestamp = datetime.now()
        datestr = timestamp.strftime("%m/%d/%Y, %H:%M:%S")

        # convert to bytes
        datestrb = c.string2bytes(datestr)
        sent = c.string2bytes(str(0))

        # encrypt sensitive information for the database
        ciphertext = c.encrypt_db(plaintext, DB_KEY, messageIV)
        enc_timestamp = c.encrypt_db(datestrb, DB_KEY, messageIV)
        enc_sent = c.encrypt_db(sent, DB_KEY, messageIV)

        # add message to database
        MessageID = DATABASE.new_message(USER_ID,
                                         CONTACT_LIST[index][0],
                                         c.bytes2string(
                                             c.bytes2base64(messageIV)),
                                         c.bytes2string(
                                             c.bytes2base64(ciphertext)),
                                         c.bytes2string(
                                             c.bytes2base64(enc_timestamp)),
                                         c.bytes2string(
                                             c.bytes2base64(enc_sent)))

        # Add the new message to MESSAGE_LIST and update the GUI if appropriate
        new_message = [USER_ID, CONTACT_LIST[index][0], MessageID,
                       messageIV, plaintext, datestr, 0]

        MESSAGE_LIST.append(new_message)

        return True

    # Below are automatic key exchange protocol messages.
    # These messages should not be kept in the database
    elif message.flag == 'a1':
        # flag a1: step 1 of the public key exchange
        public_key = message.message

        # add public_key to contact in CONTACT_LIST
        CONTACT_LIST[index][6] = public_key

        # encrypt the public key before storing in the database
        enc_public_key = c.encrypt_db(public_key, DB_KEY,
                                      CONTACT_LIST[index][1])

        DATABASE.store_pub_key(c.bytes2string(c.bytes2base64(enc_public_key)),
                               CONTACT_LIST[index][0])

        # NETWORKING: send this message
        new_message = Message(USER_ID, machineID, 'a2',
                              PUBLIC_KEY, friendcode=FRIENDCODE)
        send_message(new_message, CONTACT_LIST[index])

        return True

    elif message.flag == 'a2':
        # flag a2: step 2 of the public key exchange
        public_key = message.message

        # add public_key to contact in CONTACT_LIST
        CONTACT_LIST[index][6] = public_key

        # encrypt the public key before storing in the database
        enc_public_key = c.encrypt_db(public_key, DB_KEY,
                                      CONTACT_LIST[index][1])

        DATABASE.store_pub_key(c.bytes2string(c.bytes2base64(enc_public_key)),
                               CONTACT_LIST[index][0])

        # initiate diffie hellman key exchange
        DIFFIE_HELLMAN = c.DiffieHellman()
        g, p = DIFFIE_HELLMAN.create_gp()
        value = DIFFIE_HELLMAN.create_value()

        # NETWORKING: send this message
        new_message = Message(USER_ID, machineID, 'b1', (g, p, value),
                              friendcode=FRIENDCODE)
        send_message(new_message, CONTACT_LIST[index])

        return True

    elif message.flag == 'b1':
        # flag b1: step 1 of the diffie hellman key exchange
        g, p, value = message.message
        DIFFIE_HELLMAN = c.DiffieHellman(g, p)
        other_value = DIFFIE_HELLMAN.create_value()

        key = DIFFIE_HELLMAN.create_key(value)

        # add key to contact in CONTACT_LIST - this completes the contact
        CONTACT_LIST[index][5] = key

        # first encrypt the key
        enc_key = c.encrypt_db(key, DB_KEY, CONTACT_LIST[index][1])

        # update the database with the key
        DATABASE.store_sec_key(c.bytes2string(c.bytes2base64(enc_key)),
                               CONTACT_LIST[index][0])

        # NETWORKING: send this message
        new_message = Message(USER_ID, machineID, 'b2', other_value,
                              friendcode=FRIENDCODE)
        send_message(new_message, CONTACT_LIST[index])

        return True

    elif message.flag == 'b2':
        value = message.message

        key = DIFFIE_HELLMAN.create_key(value)

        # add key to contact in CONTACT_LIST - this completes the contact
        CONTACT_LIST[index][5] = key

        # first encrypt the key
        enc_key = c.encrypt_db(key, DB_KEY, CONTACT_LIST[index][1])

        # update the database with the key
        DATABASE.store_sec_key(c.bytes2string(c.bytes2base64(enc_key)),
                               CONTACT_LIST[index][0])

        return True

    else:
        print("Message Flag Error")
        return False


def create_message(text, contact):
    """
    Creates a message object with the given text addressed to the given contact

    param:
        text: str
        contact: list
    return: nothing
    """
    # get necessary info
    text = c.string2bytes(text)
    machineID = contact[2]
    secret_key = contact[5]
    # create message
    ciphertext, tag, nonce = c.encrypt_mssg(text, secret_key)
    signature = c.create_signature(text, PRIVATE_KEY)
    message = Message(USER_ID, machineID, 'm', ciphertext, signature,
                      FRIENDCODE, tag, nonce)
    return message


# contact in CONTACT_LIST
# [ContactID, IV, MachineID, Contactname,
# IP_address, SecretKey, PublicKey, Port#]
def send_message(message, contact):
    """
    Sends a message object to the requested contact.
    Also stores sent message in database.

    :param
        message: message object
        contact: list
    :return
        1 is sucessful, 0 if not
    """

    # get necessary info
    ip_address = contact[4]
    port = contact[7]

    # create a socket
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # try connecting the socket to the given host and port
    try:
        client.connect((ip_address, port))
    except:
        print("Connection Error to", (ip_address, port))
        return 0

    # pickle the message object and send it
    pickled_message = pickle.dumps(message)

    client.send(pickled_message)

    # close the connection
    client.close()

    # we only want to store messages with the 'm' flag
    if message.flag == 'm':
        # create secret key from contact
        secret_key = contact[5]

        # decrypt message
        plaintext = c.decrypt_mssg(message.message, secret_key,
                                   message.tag, message.nonce)

        # create message iv
        messageIV = c.create_iv()

        # create timestamp and string representation
        timestamp = datetime.now()
        datestr = timestamp.strftime("%m/%d/%Y, %H:%M:%S")

        # convert to bytes
        datestrb = c.string2bytes(datestr)
        sent = c.string2bytes(str(1))

        # encrypt sensitive information for the database
        ciphertext = c.encrypt_db(plaintext, DB_KEY, messageIV)
        enc_timestamp = c.encrypt_db(datestrb, DB_KEY, messageIV)
        enc_sent = c.encrypt_db(sent, DB_KEY, messageIV)

        # add message to database
        MessageID = DATABASE.new_message(USER_ID,
                                         contact[0],
                                         c.bytes2string(
                                             c.bytes2base64(messageIV)),
                                         c.bytes2string(
                                             c.bytes2base64(ciphertext)),
                                         c.bytes2string(
                                             c.bytes2base64(enc_timestamp)),
                                         c.bytes2string(
                                             c.bytes2base64(enc_sent)))

        # add new message to MESSAGE_LIST
        new_message = [USER_ID, contact[0], MessageID,
                       messageIV, plaintext, datestr, 1]
        MESSAGE_LIST.append(new_message)

    return 1


def start_server(user_id: int, db_key: bytes, user_iv: bytes,
                 public_ip: str, server_ip: str, port: int,
                 friendcode: str, public_key: bytes, private_key: bytes):
    """
    The purpose of this function is to
    (a) create a server socket
    (b) listen for connections
    (c) handle incoming messages
    """
    # need to update global variables for when this server
    # is run in a separate thread from the flask server
    global USER_ID, DB_KEY, PUBLIC_KEY, PRIVATE_KEY, \
        USER_IV, PUBLIC_IP, SERVER_IP, PORT, FRIENDCODE
    USER_ID = user_id
    DB_KEY = db_key
    USER_IV = user_iv
    PUBLIC_IP = public_ip
    FRIENDCODE = friendcode
    SERVER_IP = server_ip
    PORT = port
    PUBLIC_KEY = public_key
    PRIVATE_KEY = private_key

    # create a socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

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
            thread = threading.Thread(target=receive_message,
                                      args=[connection, address])
            thread.start()
        except:
            print('thread did not start')
            traceback.print_exc()


if __name__ == "__main__":
    # start the message server
    start_server(None, None, None, None, None, None, None, None, None)
