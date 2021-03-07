#########################
#       database.py     #
#                       #
# AUTHORS:              #
# Lannin Nakai          #
# Evan Podrabsky        #
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
import csv

"""
    Database class creates an sql database object that we 
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
        self.cursor = self.connection.cursor()

        # This is used whenever we need to call insert(),
        # it will be used to specify which columns to update

        # These below  columns do not contain UserID, ContactID, and MessageID respectively since those
        # values are handled by the AUTOINCREMENT feature in each of them
        self.USER_COLUMNS = ("Username", "PasswordHash", "IV", "IP_address", "Port", "PublicKey", "PrivateKey")
        self.CONTACTS_COLUMNS = ("Users_UserID", "IV", "MachineID", "ContactName", "IP_address", "Port", "SecretKey", "PublicKey")
        self.MESSAGES_COLUMNS = ("CONTACTS_USER_UserID", "CONTACTS_ContactID", "IV", "Text", "Timestamp", "Sent")

        # USER_COLUMNS with UserID added
        self.user_columns = ("UserID", "Username", "PasswordHash", "IV", "IP_address", "Port", "PublicKey", "PrivateKey")

        # Note : in this program, varchar is used to store both strings and
        # what the rest of the program will regard as python bytestrings
        # here python bytestrings are handled in str form\

        #TODO this above mentioned conversion in networking or in this script



    """
    create_users creates a users table, we can store chat room users here

    Parameters
        None
    Returns
        None
    """
    def create_users(self):

        # create users table
        self.cursor.execute("CREATE TABLE users (UserID INTEGER PRIMARY KEY, Username VARCHAR(45), PasswordHash VARCHAR(45), IV VARCHAR(45), IP_address VARCHAR(45), Port INT, PublicKey VARCHAR(2000), PrivateKey VARCHAR(2000))")

        self.connection.commit()

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
        self.cursor.execute("CREATE TABLE contacts (USERS_UserID INT, ContactID INTEGER PRIMARY KEY, IV VARCHAR(45), MachineID INT, ContactName VARCHAR(45), IP_address VARCHAR(45), Port INT, SecretKey VARCHAR(2000), PublicKey VARCHAR(2000))")
        
        self.connection.commit()
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
        self.cursor.execute("CREATE TABLE messages (CONTACTS_USER_UserID INT, CONTACTS_ContactID INT, MessageID INTEGER PRIMARY KEY, IV VARCHAR(45), Text VARCHAR(255), Timestamp DATETIME, Sent INT)")

        self.connection.commit()

        return 

    """
    insert data (values) into a table. Data will be appended to the end of the database
  
    Parameters
        table : name of table user wants to access
        values : list of values to be inserted in the new row of the table
    Returns
        None
    """
    def insert(self, table : str, columns: tuple, values : tuple)->None:

        value_args = []
        for i in range(len(columns)):
            value_args.append('?')

        args_string = ', '.join(value_args)
        args_string = '(' + args_string + ')'

        # THIS IS QUESTIONABLE (apparently susceptible to SQL injection)
        command = "INSERT INTO {0} {1} VALUES {2}".format(table, columns, args_string)

        self.cursor.execute(command, (values))
        self.connection.commit()

        return

    """
    get a users contact key from contacts table using their contact_id as an identifier

    Parameters
        contact_id : contact_id of user whose SecretKey we want to retrieve
    Returns
        SecretKey : key for decrpytion
    """
    def contact_key(self, contact_id) -> str:
        
        return self.cursor.execute("SELECT SecretKey "
                                   "FROM contacts "
                                   "WHERE contactID = ?",
                                   (contact_id,)).fetchone()

    """
    store a key on a users SecretKey using their contact_id as an identifier
    
    Parameters
        key : key we would like to save to SecretKey belonging to contact_id user
        contact_id : id of the contact we'd like to attatch the key to
    Returns
        None
    """
    def store_key(self, key, contact_id)-> None:

        # THIS IS THE RECOMMENDED WAY OF EXECUTING ARGUMENTS
        self.cursor.execute("UPDATE contacts "
                            "SET SecretKey = ? "
                            "WHERE contactID = ? ",
                            (key, contact_id))
        return

    """
    returns the users list of contacts

    Parameters
        user : user's contact_id (might not be necessary to have)
    Returns
        all contact list information as a list
    """
    def list_of_contacts(self, UserID : int)-> list:
        
        return self.cursor.execute("SELECT * "
                                   "FROM contacts "
                                   "WHERE Users_UserID=?",
                                   (UserID,)).fetchall()

                                   
    
    """
    loads a table to a csv file in the current directory
    new file made if name doesn't match currently existing files in the current directory
    
    Paramerters:
        table : the table from the database you want to save
    Return:
        None, but side effect produces a file name output.csv with desired table saved
        to it
    """
    def load_table(self, table: str):
        
        # get all of the data from the table
        data = self.cursor.execute("SELECT * FROM {table}")

        # open a file named output.csv (if it doesn't already exist, a new file
        # will be created) and save the data on it.
        with open('output.csv', 'wb') as f:
            
            # open file with writer
            writer = csv.writer(f)

            # write data inside file
            writer.writerows(data)
        
        return

    """
    closes connection to database
    """
    def close(self):

        self.connection.close()
        
        return
        

    """
    create a new user and return the UserID
    Note: the first user should have UserID=0 and each subsequent user's UserID should be incremented by 1
    
    Parameters:
        Username : name of user to be created
        PasswordHash : hash of passwords
        IV : initialization vector for decryption
        IP_address : users ip address
        Port : the port the user will be communicating through
        PublicKey : encryption key
        PrivateKey : encryption key
    Return:
        UserID : the newly created user's id
    """
    def new_user(self, Username : str, PasswordHash : str,
                 IV : str, IP_address : str, Port : str,
                 PublicKey : str, PrivateKey: str)->int:

        # set id equal to current counter value
        #UserID = self.user_counter

        # insert the new user into our users table
        self.insert("users", self.USER_COLUMNS, (Username,
                                                 PasswordHash, IV,
                                                 IP_address, Port,
                                                 PublicKey, PrivateKey))


        # increment by 1, so the next user will 
        # get a unique id (done by auto increment in UserID)
        UserID = self.cursor.execute("SELECT Users_UserID FROM users WHERE Username=?",(Username,)).fetchone()[0]

        return UserID

    """
        create a new contact. 
        Note: the first contact should have ContactID=0 and each subsequent contact's ContactID should be incremented by 1
        
        Parameters:
            values = [
                UserID : users id,
                IV : initialization vector for decryption,
                MachineID : user's machine id,
                Contactname : contact's name,
                IP_address : user's ip address,
                Port : port contact commmunicates on,
                SecretKey : encryption key,
                PublicKey : encryption key ]
        Return:
            newly created contacts id
    
    values = [UserID : int, IV : str, MachineID : int,
                    Contactname : str, IP_address : str, Port : int,
                    SecretKey: str, PublicKey: str]
    """
    def new_contact(self, values : tuple)->int:

        # insert the new contact into our contacts table
        self.insert("contacts",self.CONTACTS_COLUMNS, values
        # this value will be incremented every time it is assigned
        # via AUTOINCREMENT
        ContactID = self.cursor.execute("SELECT ContactID FROM contacts WHERE IV=?", (values[1],)).fetchall()

        # HAVING TROUBLE GETTING CONTACTID
        return ContactID

    
    """
    create a new message
    Note: the first message should have MessageID=0 and each subsequent message's MessageID should be incremented by 1
    Note: import datetime to create a timestamp whenever a new message is created
    
    Parameters:
        UserID : user's id
        ContactID : contact's id
        IV : initialization vector for encryption
        Text : contents of the message
        Sent : whether or not the message was sent (1 if sent, 0 if not)
    Return:
        MessageID : the id of the newly created message
    """
    def new_message(self, UserID : int, ContactID : int,
                    IV : str, Text : str, Sent : int)-> int:

        # insert the new message into our messages table
        self.insert("messages", [UserID, ContactID, IV, Text, Sent])

        # commit the changes to the database so we can access them
        self.connection.commit()

        MessageID = self.cursor.execute("SELECT MessageID FROM messages WHERE IV=?", (values[2]),).fetchone()[0]

        return MessageID


    """
    find a user based on the username
    
    Parameters:
        username : name of the user we want to get the information of
    Return:
        list of the found user's information
    """
    def find_user(self, username : str)-> list:
        # username = f'{username}'
        # print("SELECT {0} FROM users WHERE Username = '{1}'".format(self.USER_COLUMNS, username))
        user_columns = ", ".join(self.user_columns)
        # print(user_columns)

        # THIS IS QUESTIONABLE (apparently susceptible to SQL injection)
        return self.cursor.execute("SELECT {0} "
                                   "FROM users "
                                   "WHERE Username = '{1}'".format(user_columns, username)).fetchall()

    """
    return all contacts of a user
    
    Parameters:
        UserID : id of the user whose contacts are being searched (may not be necessary)
    Return: 
        list (nested) e.g. [[ContactID, IV, MachineID, Contactname, IP_address, Port, SecretKey, PublicKey],...]
    """
    def find_contacts(self, UserID):
        
        return self.list_of_contacts(UserID)

    """
    find the n most recent messages (sent or received) between UserID and ContactID
    
    Parameters:
        UserID : user id (might not be necessary)
        ContactID : conversation partner id
        n : number of messages user wants returned
    Return:
        list (nested) e.g. [[UserID, ContactID, MessageID, IV, Text, Timestamp, Sent],...]
    """
    def find_messages(self, UserID, ContactID, n):
        entries = self.cursor.execute("SELECT * FROM messages WHERE UserID = ?, ContactID = ?", (UserID, ContactID))

        return entries[:n]

