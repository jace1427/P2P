###########
# AUTHORS #
################
# Lannin Nakai #
################

###########
# IMPORTS #
###########

from database import database
import sqlite3
import unittest
import os

#########
# NOTES #
#########

# remove the testing database from the working directory after each execution
# of this test suite. If this is not done, then the program will error as it
# tries to make a database and tables that already exist

# create our database to do testing with
db = database("testdb")


class TestDatabaseMethods(unittest.TestCase):
    """
    Parameters
        None
    Returns
        None
    """

    def test_create_database(self):
        """
        Test if a database with the correct name is made by the database
        initialization function

        Parameters
            None
        Returns
            None
        """

        # check our working directory for our new database file
        # this is done using the os library, which allows us to check
        # the status of our file system
        self.assertEqual(True, os.path.exists("testdb"), "Database file was successfully made \n")

    def test_create_tables(self):
        """
        Test if the test database's add tables method works correctly
        for each table (users, contacts, messages)

        Parameters
            None
        Returns
            None
        """

        # create each of the tables
        # first the users table, which stores the credentials of clients who
        # have registered an account on the machine being used
        db.create_users()

        # then create the contacts table, which stores the logged in
        # users contacts
        db.create_contacts()

        # finally, create  the messages table to store the chat logs
        # between the user and their contacts
        db.create_messages()

        # check to see each of the tables exist in the database
        self.assertEqual(sqlite3.Cursor, type(db.cursor.execute("SELECT * FROM users")), "Users table was successfully made\n")
        self.assertEqual(sqlite3.Cursor, type(db.cursor.execute("SELECT * FROM contacts")), "Contacts table was successfully made\n")
        self.assertEqual(sqlite3.Cursor, type(db.cursor.execute("SELECT * FROM messages")), "Messages table was successfully made\n")

    def test_populate_tables(self):
        """
        Test if the tables in the database are properly populated via
        the database classes insertion method

        Parameters
            None
        Returns
            None
        """

        # make an entry into the users table (the information we enter doesn't
        # matter since we won't be doing anything with it, just checking that
        # it exists)
        db.insert("users",db.USER_COLUMNS ,["bob", "blah", "blah", 123, 3, "blah", "blah"])

        # make an entry into the contacts table
        db.insert("contacts", db.CONTACTS_COLUMNS, [1, "blah", 123, "blah", 123, 123, "blah", "blah"])

        # make an entry into the messages table
        db.insert("messages", db.MESSAGES_COLUMNS, [3, 4, "blah", "blah", "blah", 1])

        # check that all the tables have been filled with an entry
        self.assertNotEqual([], db.cursor.execute("SELECT * FROM users"), "Users table was successfully populated\n")
        self.assertNotEqual([], db.cursor.execute("SELECT * FROM contacts"), "Contacts table was successfully populated\n")
        self.assertNotEqual([], db.cursor.execute("SELECT * FROM messages"), "Messages table was successfully populated\n")

    def test_search_tables(self):
        """
        Test that we can search through our tables

        Parameters
            None
        Returns
            None
        """

        # check that all tables can be searched for the previously
        # inserted values
        self.assertNotEqual(db.find_user("bob"), [], "Users table was successfully searched\n")
        self.assertNotEqual(db.find_messages(3,4,1), [], "Messages table was successfully searched\n")
        self.assertNotEqual(db.find_contacts(1), [], "Contacts table was successfully searched\n")


if __name__ == '__main__':
    unittest.main()
    db.close()
