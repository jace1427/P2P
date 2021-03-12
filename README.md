# P2PSecure

-----------
### Table of Contents

1. [About the Project](link)

	- [Built With](link)

2. [Installation](link)

3. [User Guide](link)

	- [Getting Started](link)
	- [Messaging](link)

4. [Roadmap](link)

5. [Contacts](link)

-----------
## About the Project
P2PSecure is a secure message chat application that places focus on privacy and data security. User information, contacts, and messages are encrypted and stored on a database that exists only on the local machines of the users. 

This is an attempt to create a trustless system, without a centralized server that holds onto all user information/messages. 

### Built With
Users interact with the application through their web browser. The website is created through the use of HTML, CSS, JS, and the web pages are displayed via Flask.\
[Flask Documentation](https://flask.palletsprojects.com/en/1.1.x/)

Sending and receving messages is handled with standard python socketing and multiprocessing/threading libraries.\
[python socket documentation](https://docs.python.org/3/library/socket.html)

Cryptography functions are built with the pycryptodome libraries.\
[pycryptodome documentation](https://pypi.org/project/pycryptodome/)

The database uses SQL and is built with pysqlite3.\
[pysqlite3 documentation](https://pypi.org/project/pysqlite3/)

## Installation 

TODO

## User Guide

### Getting Started

1. Start the application by running... 
2. In your web browser navigate to 127.0.0.1:5000
3. Select 'First-time user click here' on the log in page to go to the registration page.
4. Enter a username and password then select 'Resgister'
5. Upon successful registration you will be taken back to the log in page.
6. Enter your credentials from step 4 and select 'Log in'.
7. Upon sucessful log in, you will be taken to the main page.

### Messaging

Located on the main page are two main areas, the Message Log and the Contacts section.
Under the Contacts section you will see your username displayed along with your friendcode.
This friendcode is all you need to share with someone you want to chat with. It is a special number that contains your ip address, port number, and user ID.

Below your friendcode is where you can enter the name and friendcode of someone you want to add as a contact. Simply enter the information into the designated text boxes and select 'Add Contact'.

[RESERVED FOR KEY EXCHANGE DETAILS]

Once keys have been exchanged, messages can be sent. Select the 'Message' button next to the contact you wish to message. Selecting the 'Message' button should populate the chat log with any messages stored in the database between you and the selected contact.

Once a contact has been selected, enter your message into the text box under the Message Log and select 'Send'. 

NOTE: successful messaging relies on both parties being online and logged in to the application.

## Roadmap

There are many things we have learned over the course of this project, and we have several ideas for the future ahead.

	- Future features
	- Improved networking
	- Improved UI
	- Robust testing

## Contacts

Adam Christensen\
Riley Matthews - rmatthe2@uoregon.edu\
Lannin Nakai\
Evan Podrabsky\
Justin Spidell