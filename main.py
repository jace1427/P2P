"""
Main
2021/02/22

NOTE: A lot of these functions and classes will probably be moved to the network/GUI module
"""
import cryptography as c
import database as d

USER_ID = 0
CONTACT_LIST = []  # [[ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey],...]
MESSAGE_LIST = []  # [[(text, bool), (text, bool),...],[(text, bool), (text, bool),...],...]
KEY = None
PUBLIC_KEY = None
PRIVATE_KEY = None  # might need to make a database call everytime the private key is needed rather that do this
DIFFIE_HELLMAN = None
#DATABASE = None


class Message:
    def __init__(self, user_id, contact_id, message, signature, flag='m', tag=None, nonce=None):
        self.user_ID = user_id
        self.contact_ID = contact_id
        self.message = message
        self.signature = signature
        self.flag = flag
        self.tag = tag
        self.nonce = nonce


def encode(ip_address, user_id):
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


def decode(friendcode):
    friendcode = int(friendcode, 16)
    ip_address = []
    while friendcode != 0:
        ip_address.append(friendcode & 255)
        friendcode = friendcode >> 8
    contact_id = ip_address.pop(0)
    print(ip_address)
    ip_address = '.'.join(map(str, ip_address))
    return contact_id, ip_address


def create_account(username, password):
    # check if username is unique. Use CONTACT_LIST
    # check if password is secure (just check length?)
    # create public and private key
    # create friendcode
    # encrypt friendcode, publicKey, privateKey
    # TODO DATABASE: create a new user
    return NotImplementedError


def login(username, password):
    global KEY
    global CONTACT_LIST
    global USER_ID
    # Step 1: Authenticate User
    password_hash = c.pwd2hash(c.string2bytes(password))
    #TODO DATABASE: find user based on username and return all of the user's data in a list
    """if (password_hash == PasswordHash):
        KEY = c.pwd2key(c.string2bytes(password))
    else:
        print("Wrong Password")
        return False"""
    # Step 2: get user USERID, PUBLIC_KEY, PRIVATE_KEY

    # Step 3: Create Contact List
    #TODO DATABASE: return all contacts of a specific User (You'll need to JOIN USERS and CONTACTS)
    # Create CONTACT_LIST = [[ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey],...]
    for contact in CONTACT_LIST:
        i = 2
        while i != 5:
            contact[i] = c.decrypt_db(contact[i], KEY, contact[1])
    # Step 4: Pull most recent messages of each user
    #TODO DATABASE: create a function that returns the n most recent messages of a user
    return NotImplementedError

# [[ContactID, IV, MachineID, Contactname, IP_address, SecretKey, PublicKey]
def add_contact(friendcode, public_key=None):
    global CONTACT_LIST
    contact_id, ip_address = decode(friendcode)
    #TODO Generate new contact ID
    CONTACT_LIST.append(['Contact_ID_PLACEHOLDER', None, contact_id, ip_address, None, public_key])
    return send_message(None, contact_id, 'k')


def receive_message(message, ip_address):
    #TODO: need to check if message.contact_ID == USER_ID
    global MESSAGE_LIST
    global DIFFIE_HELLMAN
    # find contact
    contact = None
    for i in range(len(CONTACT_LIST)):
        if CONTACT_LIST[i][4] == ip_address and CONTACT_LIST[i][2] == message.user_ID:
            contact = CONTACT_LIST[i]
            break
    if contact is None:
        print("Invalid Contact")
        return False
    if message.flag == 'm':
        # decrypt message
        secret_key = contact[5]
        plaintext = c.decrypt_mssg(message.message, secret_key, message.tag, message.nonce)
        # encrypt message for the database
        iv = c.create_iv()
        ciphertext = c.encrypt_db(plaintext, KEY, iv)
        # TODO DATABASE: create a new message given: UserID, ContactID, IV, Text
        MESSAGE_LIST[i].append((plaintext, 0))
        # TODO not sure what to return here
        return None
    elif message.flag == 'a':
        g = message.message[0]
        p = message.message[1]
        value = message.message[2]
        machineID = message.user_ID  # not a typo
        userID = message.contact_ID  # not a typo
        DIFFIE_HELLMAN = c.DiffieHellman(g, p)
        value = DIFFIE_HELLMAN.create_value()
        key = DIFFIE_HELLMAN.create_key(value)
        # TODO: add key to a bunch of stuff...
        ip_address = CONTACT_LIST[-1][4]  # feels jank to use -1
        message = send_message(value, CONTACT_LIST[-1][0], 'b')  # feels jank to use -1
        return message, ip_address
    elif message.flag == 'b':
        value = message.message
        key = DIFFIE_HELLMAN.create_key(value)
        # TODO: add key to a bunch of stuff...
        return key
    elif message.flag == 'k':
        ip_address = CONTACT_LIST[-1][4]  # feels jank to use -1
        contactID = CONTACT_LIST[-1][0]  # feels jank to use -1
        public_key = message.message
        # add public_key to contact information
        message = send_message(None, contactID, 'j')
        return message, ip_address
    elif message.flag == 'j':
        ip_address = CONTACT_LIST[-1][4] # feels jank to use -1
        contactID = CONTACT_LIST[-1][0]  # feels jank to use -1
        public_key = message.message
        # add public_key to contact information
        message = send_message(None, contactID, 'a')
        return message, ip_address
    else:
        print("Message Flag Error")
        return False


def send_message(text, contactID, flag='m'):
    # find contact
    contact = None
    for person in CONTACT_LIST:
        if person[0] == contactID:
            contact = person
            break
    if contact is None:
        print("Invalid Contact ID")
        return False
    ip_address = contact[4]
    machineID = contact[2]
    # create message
    if flag == 'm':
        secret_key = contact[5]
        ciphertext, tag, nonce = c.encrypt_mssg(text, secret_key)
        signature = c.create_signature(text, PRIVATE_KEY)
        message = Message(USER_ID, machineID, ciphertext, signature, flag, tag, nonce)
        return message, ip_address
        # TODO NETWORK: if message with flag 'm' is successfully sent, then add message to database
    elif flag == 'a':
        # initiate Diffie Hellman
        global DIFFIE_HELLMAN
        DIFFIE_HELLMAN = c.DiffieHellman()
        g, p = DIFFIE_HELLMAN.create_gp()
        value = DIFFIE_HELLMAN.create_value()
        message = Message(USER_ID, machineID, [g, p, value], None, 'a')
        return message, ip_address
    elif flag == 'b':
        # response to Diffie Hellman
        if text is None:
            global DIFFIE_HELLMAN
            value = DIFFIE_HELLMAN.create_value()
        else:
            value = text
        message = Message(USER_ID, value, None, 'b')
        return message, ip_address
    elif flag == 'k':
        message = Message(USER_ID, machineID, PUBLIC_KEY, None, 'k')
        return message, ip_address
    elif flag == 'j':
        message = Message(USER_ID, machineID, PUBLIC_KEY, None, 'j')
        return message, ip_address
    else:
        print("Message Flag Error")
        return False

