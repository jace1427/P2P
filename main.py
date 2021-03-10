"""
Main
2021/02/26

NOTE: A lot of these functions and classes will probably be moved to the network/GUI module
NOTE: the cryptography module uses byte strings (e.g. b'this is a byte') and database might also.
NOTE: what is not included in this code/skeleton is how to verify if a message has been received
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
import ctypes

# general
from datetime import datetime


USER_ID = 0            # Every user on the local system will have their own ID.
USERNAME = ""          # Empty string to represent user
FRIENDCODE = ""
CONTACT_LIST = []      # [[ContactID, IV, MachineID, ContactName, IP_address, SecretKey, PublicKey, Port#],...]
MESSAGE_LIST = []      # [[MessageID, IV, Text, Timestamp, Sent],...]
USER_IV = None         # the IV created for the user when they made their account. Used for db encryption
DB_KEY = None          # key used for encrypting and decrypting entries in the database
PUBLIC_KEY = None      # Users public key
PRIVATE_KEY = None     # Users private key
DIFFIE_HELLMAN = None  # diffie hellman object. see cryptography.py
LOCAL_IP = None
SERVER_THREAD = None


# networking constants
BUFSIZE = 4096  # TODO enforce this somewhere
FORMAT = 'utf-8'  # probably not needed
SERVER_IP = socket.gethostbyname(socket.gethostname())
# SERVER_IP = "10.0.0.164"
PORT = 5550


def kill_thread(thread):
    """
    thread: a threading.Thread object

    Credit to stackoverflow user "serg06"
    """
    global SERVER_THREAD
    thread_id = thread.ident
    res = ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, ctypes.py_object(SystemExit))
    print("res: ", res)
    if res > 1:
        ctypes.pythonapi.PyThreadState_SetAsyncExc(thread_id, 0)
        print('Exception raise failure')
    SERVER_THREAD = None


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


def encode_friend(ip_address: str, user_id: int, port: int):
    print(ip_address)
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


# TODO Will need updating with friendcode that takes port
def create_account(username: str, password: str):

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
    UserID = DATABASE.new_user(username.lower(),
                               c.bytes2string(c.bytes2base64(PasswordHash)),
                               c.bytes2string(c.bytes2base64(User_IV)),
                               c.bytes2string(c.bytes2base64(enc_IP_address)),
                               c.bytes2string(c.bytes2base64(enc_PORT)),
                               c.bytes2string(c.bytes2base64(enc_PublicKey)),
                               c.bytes2string(c.bytes2base64(enc_PrivateKey)))
    #DATABASE.close()

    print(f"New user {username} created! "
          f"UserID: {UserID}")

    # global variables will need to be set in login, but this may change
    # when we figure out how to make flask and sql play nice
    return 0


# contact in CONTACT_LIST [ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey]
def login(username, password):

    global DB_KEY, USER_ID, PUBLIC_KEY, PRIVATE_KEY, \
        USER_IV, CONTACT_LIST, DATABASE, USERNAME, \
        FRIENDCODE, SERVER_THREAD, SERVER_THREAD_LOCAL

    if not username or not password:
        # print("Username and password cannot be blank")
        return -1
    elif "'" in username or "'" in password:
        # print("Username and password cannot contain '")
        return -2

    # Step 0: find if user with given username exists in the system
    user_info = DATABASE.find_user(username.lower())
    if user_info:
        user_info = user_info[0]
        # print(user_info)
        print(f"User {user_info[1]} found!")
        PasswordHash = c.base642bytes(c.string2bytes(user_info[2]))
        if CONTACT_LIST:
            CONTACT_LIST.clear()
        # if MESSAGE_LIST:
        #     MESSAGE_LIST.clear()
    else:
        # database will return empty list if user not found
        print("User not found")
        return -3

    # Step 1: Authenticate User
    password_hash = c.pwd2hash(c.string2bytes(password))

    # Step 2: check if password's hash matches stored hash
    # print(password_hash)
    # print(PasswordHash)
    if (password_hash == PasswordHash):
        # Step 2a (if step 2 is a success): set global variables
        print("Password was correct!")
        # if the correct password is entered
        DB_KEY = c.pwd2key(c.string2bytes(password))
        USER_ID = int(user_info[0])
        USERNAME = user_info[1]
        USER_IV = c.base642bytes(c.string2bytes(user_info[3]))
        LOCAL_IP = c.bytes2string(c.decrypt_db(c.base642bytes(c.string2bytes(user_info[4])), DB_KEY, USER_IV))
        User_PORT = int(c.bytes2string(c.decrypt_db(c.base642bytes(c.string2bytes(user_info[5])), DB_KEY, USER_IV)))
        FRIENDCODE = encode_friend(LOCAL_IP, USER_ID, User_PORT)
        PUBLIC_KEY = c.decrypt_db(c.base642bytes(c.string2bytes(user_info[6])), DB_KEY, USER_IV)
        PRIVATE_KEY = c.decrypt_db(c.base642bytes(c.string2bytes(user_info[7])), DB_KEY, USER_IV)
    else:
        print("Incorrect password")
        # if the wrong password is entered
        return -4


    # Step 3: Populate Contact List global variable
    _populate_contact_list(USER_ID)

    # Step 4: start server
    SERVER_THREAD = multiprocessing.Process(target=start_server, args=(USER_ID, DB_KEY))


    return 0


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
        new_contact.append(int(c.bytes2string(c.decrypt_db(
            c.base642bytes(c.string2bytes(contact[3])), DB_KEY, new_contact[1]))))

        # Contact name (decrypt)
        new_contact.append(c.bytes2string(c.decrypt_db(
            c.base642bytes(c.string2bytes(contact[4])), DB_KEY, new_contact[1])))

        # IP address (decrypt)
        new_contact.append(c.bytes2string(c.decrypt_db(
            c.base642bytes(c.string2bytes(contact[5])), DB_KEY, new_contact[1])))

        # Secret key (decrypt)
        new_contact.append(c.bytes2string(c.decrypt_db(
            c.base642bytes(c.string2bytes(contact[7])), DB_KEY, new_contact[1])))

        # Public key (decrypt)
        new_contact.append(c.bytes2string(c.decrypt_db(
            c.base642bytes(c.string2bytes(contact[8])), DB_KEY, new_contact[1])))

        # Port (decrypt)
        new_contact.append(int(c.bytes2string(c.decrypt_db(
            c.base642bytes(c.string2bytes(contact[6])), DB_KEY, new_contact[1]))))
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
    # might want to clear whatever messages are in the list before populating
    MESSAGE_LIST = []

    temp_message_list = DATABASE.find_messages(UserID, ContactID)
    for message in temp_message_list:
        new_message = []

        # MessageID (no decrypt)
        new_message.append(int(message[2]))

        # Initialization Vector (no decrypt)
        new_message.append(c.base642bytes(c.string2bytes(message[3])))

        # Message Text (decrypt)
        new_message.append(c.bytes2string(c.decrypt_db(
            c.base642bytes(c.string2bytes(message[4])), DB_KEY, new_message[1])))

        # Timestamp (decrypt)
        new_message.append(c.bytes2string(c.decrypt_db(
            c.base642bytes(c.string2bytes(message[5])), DB_KEY, new_message[1])))

        # Sent (decrypt)
        # Might be an Int or a string
        new_message.append(int(c.bytes2string(c.decrypt_db(
            c.base642bytes(c.string2bytes(message[6])), DB_KEY, new_message[1]))))

        MESSAGE_LIST.append(new_message)


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
    new_contact = [contactID, contactIV, machine_id, Contactname, ip_address, "temp sk", public_key, port]

    # insert new contact into CONTACT_LIST
    CONTACT_LIST.append(new_contact)

    public_key = "temp pk"

    # Convert to bytes
    machine_id  = c.string2bytes(str(machine_id))
    Contactname = c.string2bytes(str(Contactname))
    ip_address  = c.string2bytes(str(ip_address))
    port        = c.string2bytes(str(port))
    public_key  = c.string2bytes(str(public_key))
    sk          = c.string2bytes("temp sk")

    # encrypt senstitive information
    enc_machine_id  = c.encrypt_db(machine_id, DB_KEY, contactIV)
    enc_Contactname = c.encrypt_db(Contactname, DB_KEY, contactIV)
    enc_ip_address  = c.encrypt_db(ip_address, DB_KEY, contactIV)
    enc_port        = c.encrypt_db(port, DB_KEY, contactIV)
    enc_public_key  = c.encrypt_db(public_key, DB_KEY, contactIV)
    enc_secret_key  = c.encrypt_db(sk, DB_KEY, contactIV)

    # create new contact to be added to database
    new_contact_db = (USER_ID,
                     c.bytes2string(c.bytes2base64(contactIV)),
                     c.bytes2string(c.bytes2base64(enc_machine_id)),
                     c.bytes2string(c.bytes2base64(enc_Contactname)),
                     c.bytes2string(c.bytes2base64(enc_ip_address)),
                     c.bytes2string(c.bytes2base64(enc_port)),
                     c.bytes2string(c.bytes2base64(enc_public_key)),
                     c.bytes2string(c.bytes2base64(enc_secret_key)))

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
    message = Message(USER_ID, contact[2], 'a1', PUBLIC_KEY, None)

    # send the message
    send_message(message, contact)


# contact in CONTACT_LIST [ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey]
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

    print("you have received a message from: ", address)

    # NETWORK
    # get the sent message object
    # NOTE: larger messages might require the recieving to be done in a loop
    msg = connection.recv(BUFSIZE)
    message = pickle.loads(msg)

    # get machineID from message
    machineID = message.user_ID

    # check if message.machine_id == USER_ID i.e check if message is intended for the current user
    # TODO: we may have to send an error message back to the sender
    if message.machine_id != USER_ID:
        print("invalid contact\n")
        return False

    # close the connection
    connection.close()

    _populate_contact_list(USER_ID)

    # find contact in CONTACT_LIST based on ip_address and machineID
    index = 0
    for i in range(len(CONTACT_LIST)):
        if (CONTACT_LIST[i][4] == address[0]) and (CONTACT_LIST[i][2] == machineID):
            # found the right contact
            index = i
            break


    # process flags
    if message.flag == 'm':
        print("flag: m, text received!")
        #print(message.message)
        # TODO test this encryption

        # create secret key from contact
        secret_key = CONTACT_LIST[index][5]

        # decrypt message
        plaintext = c.decrypt_mssg(message.message, secret_key, message.tag, message.nonce)

        # create message iv
        messageIV = c.create_iv()

        # create timestamp and string representation
        timestamp = datetime.now()
        datestr = timestamp.strftime("%m/%d/%Y, %H:%M:%S")

        # convert to bytes
        plaintextb = c.string2bytes(str(plaintext))
        datestrb   = c.string2bytes(datestr)
        sent       = c.string2bytes(str(0))

        # encrypt sensitive information for the database
        ciphertext    = c.encrypt_db(plaintextb, DB_KEY, messageIV)
        enc_timestamp = c.encrypt_db(datestrb, DB_KEY, messageIV)
        enc_sent      = c.encrypt_db(sent, DB_KEY, messageIV)

        # add message to database
        MessageID = DATABASE.new_message(USER_ID,
                                        CONTACT_LIST[index][0],
                                        messageIV,
                                        ciphertext,
                                        enc_timestamp,
                                        enc_sent)

        # Add the new message to MESSAGE_LIST and update the GUI if appropriate
        new_message = [USER_ID, CONTACT_LIST[index][0], MessageID, messageIV, plaintext, datestr, 0]

        MESSAGE_LIST.append(new_message)

        return True

    # Below are automatic key exchange protocol messages. These messages should not be kept in the database
    elif message.flag == 'a1':
        print("flag: a1")
        # flag a1: step 1 of the public key exchange
        public_key = message.message

        # add public_key to contact in CONTACT_LIST
        CONTACT_LIST[index][6] = public_key

        # NETWORKING: send this message
        new_message = Message(USER_ID, machineID, 'a2', PUBLIC_KEY)
        send_message(new_message, CONTACT_LIST[index])

        return True

    elif message.flag == 'a2':
        print("flag: a2")
        # flag a2: step 2 of the public key exchange
        public_key = message.message

        # add public_key to contact in CONTACT_LIST
        CONTACT_LIST[index][6] = public_key

        # initiate diffie hellman key exchange
        DIFFIE_HELLMAN = c.DiffieHellman()
        g, p = DIFFIE_HELLMAN.create_gp()
        value = DIFFIE_HELLMAN.create_value()
        #print("g: ", g)
        #print("p: ", p)
        #print("value: ", value)

        # NETWORKING: send this message
        new_message = Message(USER_ID, machineID, 'b1', (g, p, value))
        send_message(new_message, CONTACT_LIST[index])

        return True

    elif message.flag == 'b1':
        print("flag: b1")
        # flag b1: step 1 of the diffie hellman key exchange
        g, p, value = message.message
        DIFFIE_HELLMAN = c.DiffieHellman(g, p)
        value = DIFFIE_HELLMAN.create_value()
        #print("g: ", g)
        #print("p: ", p)
        #print("value: ", value)
        key = DIFFIE_HELLMAN.create_key(value)

        # add key to contact in CONTACT_LIST - this completes the contact
        CONTACT_LIST[index][5] = key

        #print(CONTACT_LIST[index])

        # first encrypt the key
        enc_key = c.encrypt_db(key, DB_KEY, USER_IV)

        # update the database with the key
        DATABASE.store_key(enc_key, CONTACT_LIST[index][0])

        # NETWORKING: send this message
        new_message = Message(USER_ID, machineID, 'b2', value)
        send_message(new_message, CONTACT_LIST[index])

        return True

    elif message.flag == 'b2':
        print("flag: b2")
        value = message.message
        key = DIFFIE_HELLMAN.create_key(value)

        # add key to contact in CONTACT_LIST - this completes the contact
        CONTACT_LIST[index][5] = key

        #print(CONTACT_LIST[index])
        
        # first encrypt the key
        enc_key = c.encrypt_db(key, DB_KEY, USER_IV)

        # update the database with the key
        DATABASE.store_key(enc_key, CONTACT_LIST[index][0])

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
    ip_address = contact[4]
    machineID = contact[2]
    secret_key = contact[5]
    # create message
    ciphertext, tag, nonce = c.encrypt_mssg(text, secret_key)
    signature = c.create_signature(text, PRIVATE_KEY)
    message = Message(USER_ID, machineID, 'm', ciphertext, signature, tag, nonce)


# contact in CONTACT_LIST [ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey]
def send_message(message, contact):
    """
    Sends a message object to the requested contact.
    Also stores sent message in database.

    :param
        message: message object
        contact: list
    :return
        nothing
    """

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

    # we only want to store messages with the 'm' flag
    if message.flag == 'm':
        # create secret key from contact
        secret_key = contact[5]

        # decrypt message
        plaintext = c.decrypt_mssg(message.message, secret_key, message.tag, message.nonce)

        # create message iv
        messageIV = c.create_iv()

        # create timestamp and string representation
        timestamp = datetime.now()
        datestr = timestamp.strftime("%m/%d/%Y, %H:%M:%S")

        # convert to bytes
        plaintextb = c.string2bytes(str(plaintext))
        datestrb   = c.string2bytes(datestr)
        sent       = c.string2bytes(str(1))

        # encrypt sensitive information for the database
        ciphertext = c.encrypt_db(plaintext, DB_KEY, messageIV)
        enc_sent   = c.encrypt_db(sent, DB_KEY, messageIV)

        # add message to database
        MessageID = DATABASE.new_message(USER_ID,
                                        contact[0],
                                        messageIV,
                                        ciphertext,
                                        enc_sent)

        # add new message to MESSAGE_LIST
        new_message = [USER_ID, contact[0], MessageID, messageIV, plaintext, datestr, 1]

        MESSAGE_LIST.append(new_message)


# [[UserID, ContactID, MessageID, IV, Text, Timestamp, Sent],...]
def decipher_message_list(messages):
    for message in messages:
        message[4] = c.decrypt_db(message[4], DB_KEY, message[3])
        message[5] = c.decrypt_db(message[5], DB_KEY, message[3])
        message[6] = c.decrypt_db(message[6], DB_KEY, message[3])
    # may need to order the messages by their timestamp
    # may also want to remove unnecessary information (UserID, ContactID, IV)
    return messages


def start_server(user_id: int, db_key: bytes):
    """
    The purpose of this function is to
    (a) create a server socket
    (b) listen for connections
    (c) handle incoming messages
    """
    global USER_ID, DB_KEY, STOP_SERVER
    USER_ID = user_id
    DB_KEY = db_key

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
    print(SERVER_IP)
    start_server()
