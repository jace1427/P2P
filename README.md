# P2PSecure

-----------
### Table of Contents

1. [About the Project](#about-the-project)

	- [Built With](#built-with)

2. [Installation](#installation)

3. [User Guide](#user-guide)

	- [Getting Started](#getting-started)
	- [Adding Acontacts, Exchanging Keys, and Messaging](#Adding-Contacts,-Exchanging-Keys,-and-Messaging)
	- [Testing the Application Locally](#Testing-the-Application-Locally)
	- [Receiving messages from outside your LAN](#Receiving-messages-from-outside-your-LAN)

4. [Roadmap](#roadmap)

5. [Contacts](#contacts)

-----------
## About the Project
P2PSecure is a secure message chat application that places focus on privacy and data security. User information, contacts, and messages are encrypted and stored on a database that exists only on the local machines of the users. 

This is an attempt to create a trustless system, without a centralized server that holds onto all user information/messages. 

### Built With
Users interact with the application through their web browser. The website is created through the use of HTML, CSS, JS, and the web pages are displayed via Flask.
[Flask Documentation](https://flask.palletsprojects.com/en/1.1.x/)

Sending and receving messages is handled with standard python socketing and multiprocessing/threading libraries. Messages are sent over TCP sockets.
[python socket documentation](https://docs.python.org/3/library/socket.html)

Cryptography functions are built with the pycryptodome libraries.
[pycryptodome documentation](https://pypi.org/project/pycryptodome/)

The database uses SQL and is built with pysqlite3.
[pysqlite3 documentation](https://pypi.org/project/pysqlite3/)

## Installation 

1. Create a folder and download all the application files into that folder.
2. To install the neccessary packages run the following command in a terminal window:

```
pip install -r requirements.txt
```

## User Guide

### Getting Started

1. Start the application by running `python3 flask_p2p.py`
2. In your web browser navigate to 127.0.0.1:5000
3. Select 'First-time user click here' on the log in page to go to the registration page.
4. Enter a username and password then select 'Resgister'
5. Upon successful registration you will be taken back to the log in page.
6. Enter your credentials from step 4 and select 'Log in'.
7. Upon sucessful log in, you will be taken to the main index page.

### Adding Contacts, Exchanging Keys, and Messaging

Located on the index page are two main areas, the Message Log and the Contacts section.
Under the Contacts section you will see your username displayed along with your friendcode.
This friendcode is all you need to share with someone you want to chat with. It is a special number that contains your ip address, port number, and user ID. You will see two friendcodes displayed. One is generated using your public ipaddress, the other is generated with the localhost address (127.0.0.1). The second friendcode is used for local testing.

Below your friendcode is where you can enter the name and friendcode of someone you want to add as a contact. Simply enter the information into the designated text boxes and select 'Add Contact'.

Once a contact has been added it is time to exchange keys.

1. Select the message button next to the contacts name.
2. Select the initiate key exchange button located below the message log.

Once keys have been exchanged, messages can be sent. 

1. Select the 'Message' button next to the contact you wish to message. Selecting the 'Message' button should populate the chat log with any messages stored in the database between you and the selected contact.
2. Enter your message into the text box underneath the Message Log and select 'Send'.
3. The sent message should be displayed in the message log, along with any previous messages.

NOTE: successful messaging relies on both parties being online and logged in to the application.

### Testing the Application Locally

In order to test the messaging features of the application on your machine yourself, you will need to make a copy of the application files in another folder on your machine. Edit the copy flask_p2p.py in line [247] to use port 5001 instead of port 5000. Then edit the config.txt to use a different port, say 5555 instead of 5550.

1. Open one browser window and navigate to 127.0.0.1:5000 and open another window and navigate to 127.0.0.1:5001. 
2. Follow the "Getting Started" steps in each window. 
3. Add each other as contacts using the internal friencode.
4. In one of the windows, select the Message button next to their contact.
5. Then select the initiate key exchange button.
6. Start sending messages back and forth!

#### Receiving messages from outside your LAN

Initially the application is set to listen on the local host address '127.0.01' in the config.txt. This will work fine for receiving messages from different ports on your machine. If you want to try receving messages from outside your local network the server must be set to listen to your machines ipv4 address. This can be found in the network settings (mac) or by running /ipconfig in a cmd prompt for windows.

In order to receive messages addressed to your public ip address, it might be necessary to forward the required port in your router settings. 

[Making You Computer Accessible to the Public Internet](https://www.nch.com.au/kb/10046.html)

## Roadmap

There are many things we have learned over the course of this project, and we have several ideas for the future ahead for improvements.

- Future features
	- Chat rooms: As of now the application supports messaging between two users. A future feature would be to expand these capabilities to chat with multiple users at a time.
	- More than messages: We forsee the ability to send files, like an image for example, in addition to text messages.
- Improved networking
	- Before the application can be succesfully deployed for wide scale use we would like to improve the networking capabilities to make the application more user friendly and "plug & play". Currently the need to configure router settings is too much to ask of the general user base we would eventually like to reach.
- Improved UI features
	- Additional "nice to have" UI features.
	- Automatic message population in the chat log.
	- Online indicators to tell if your contacts are currently online.
	- Enhanced look
- Bug fixes and continued testing
	- Issues with key exchanges with multiple contacts.

## Contacts

- Adam Christensen
- Riley Matthews - rmatthe2@uoregon.edu
- Lannin Nakai
- Evan Podrabsky
- Justin Spidell