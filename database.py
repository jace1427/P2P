#########################
#       database.py     #
#                       #
# AUTHORS:              #
# Lannin Nakai          #
#                       #
#########################

##################################################
# handles database storage and accessing of data #
# sensitive data is stored in encrypted form     #
##################################################

#############
## IMPORTS ##
#############

import sqlite3


"""
    database class creates an sql database object that we 
    can store and extract data to
"""

class database():
    
    """
    Parameters 
        name : name of database

    Return
        None
    """
    def __init__(self, name : str) -> None:
        
        # connects to (or creates, if the database doesn't exist) database
        self.connection  = sqlite3.connect(name)
        
        # allows us to insert inside the database
        self.cursor = connection.cursor()

        # counter for messages (incrementally increases on each message by 1)
        # provides an indexing along the timestamps for messages
        self.message_id = 0

    """
    create_users creates a users table, we can store chat room users here

    Parameters
        None
    Returns
        None
    """
    def create_users(self):

        # create users table
        self.cursor.execute("CREATE TABLE users (userID INT, username VARCHAR(45), PasswordHash VARCHAR(45), IV VARCHAR(45), FriendCode VARCHAR(45), PublicKey VARCHAR(45), PrivateKey VARCHAR(45))")

        return

    """
    create_contacts creates a contacts table, a user can track all their contacts
    and relevant information here

    Parameters
        None
    Returns
        None
    """
    def create_contacts(self):
        
        # create contacts table
        self.cursor.execute("CREATE TABLE contacts (USERS_UserID INT, ContactID INT, IV VARCHAR(45), MachineID INT, ContactName VARCHAR(45), IP_address VARCHAR(45), SecretKey VARCHAR(45), PublicKey VARCHAR(45))")
        
        return

    """
    create_messages creates a messages table, a user can track all their contacts
    and relevant information here

    Parameters
        None
    Returns
        None
    """
    def create_messages(self):
        
        # creates messages table
        self.cursor.execute("CREATE TABLE messages (CONTACTS_USER_UserID INT, CONTACTS_ContactID INT, MessageID INT, IV VARCHAR(45), Text VARCHAR(255), Timestamp DATETIME, Sent Int)")

        return 

    """
    insert data (values) into a table. Data will be appended to the end of the database
  
    Parameters
        table : name of table user wants to access
        values : list of values to be inserted in the new row of the table
    Returns
        None
    """
    def insert(self, table : str, values : list)->None:

        self.cursor.execute(f"INSERT INTO {table} VALUES ({*values})")

        return

    """
    get a users contact key from contacts table using their contact_id as an identifier

    Parameters
        contact_id : contact_id of user whose SecretKey we want to retrieve
    Returns
        SecretKey : key for decrpytion
    """
    def contact_key(self, contact_id) -> str:
        
        return self.cursor.execute("SELECT SecretKey FROM contacts WHERE contactID = ?", (contact_id))

    """
    store a key on a users SecretKey using their contact_id as an identifier
    
    Parameters
        key : key we would like to save to SecretKey belonging to contact_id user
        contact_id : id of the contact we'd like to attatch the key to
    Returns
        None
    """
    def store_key(self, key, contact_id)-> None:
        
        self.cursor.execute("UPDATE contacts SET SecretKey = ? WHERE contactID = ? ", (key, contact_id))
        return

    """
    stores a message in the users messages log

    Parameters
        user : users contact_id
        contact_id : contact's contact_id
        iv : initialization vector for decryption
        message : message sent between the parties
        timestamp : time the message was sent
        sent : determines whether message is sent by or delivered to user
    Returns
        None
    """
    def store_message(self, user : int, contact_id : int, iv : str, message : str, timestamp : datetime, sent : int)-> None:
        
        # stores message to messages database
        self.cursor.execute(f"INSERT INTO messages VALUES ({user}, {contact_id}, {self.message_id}, {iv}, {message}, {timestamp}, {sent})")
        
        # increment self.message_id
        self.message_id = self.message_id + 1

        return

    """
    returns the users list of contacts

    Parameters
        user : user's contact_id
    Returns
        None
    """
    def list_of_contacts(self, user)-> None:
        
        return self.cursor.execute("SELECT contact_id, IP_address FROM contacts").fetchall()
