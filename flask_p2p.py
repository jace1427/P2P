"""Flask Backend for the Peer-2-Peer Messaging System.

Functions:



Author:

    Justin Spidell
    Riley Matthews
    Evan Podrabsky
"""
import flask
from flask import request
import main
# import threading

app = flask.Flask(__name__)
app.secret_key = bytes(1)

# Global variables
FLASK_USERNAME = ""
FLASK_FRIENDCODE = ""
CURRENT_RECIPIENT = 0
CURRENT_CONNECTION = ""


@app.route("/")
@app.route("/login")
def login():
    app.logger.debug("Login")
    global CURRENT_CONNECTION
    if main.SERVER_THREAD is not None:
        main.SERVER_THREAD.terminate()
        main.SERVER_THREAD = None
    CURRENT_CONNECTION = ""
    return flask.render_template("login.html")


@app.route("/login_attempt", methods=["POST"])
def login_attempt():
    app.logger.debug("Login attempt")
    global CURRENT_RECIPIENT
    username = request.form["username-input"]
    password = request.form["password-input"]
    result = main.login(username, password)
    if result == 0:
        if main.SERVER_THREAD is not None:
            CURRENT_RECIPIENT = 0
            main.SERVER_THREAD.start()
        return flask.redirect("/index")
    elif result == -1:
        flask.flash(u"ERROR: Username or password cannot be blank")
    elif result == -2:
        flask.flash(u"ERROR: Invalid username or password")
        flask.flash(
            u"Usernames and passwords may contain any character except '")
    elif result == -3:
        flask.flash(u"ERROR: User not found")
    else:
        flask.flash(u"ERROR: Incorrect password")
    return flask.redirect("/login")


@app.route("/registration")
def registration():
    app.logger.debug("Registration")
    return flask.render_template("register.html")


@app.route("/registration_attempt", methods=["POST"])
def registration_attempt():
    app.logger.debug("Registration attempt")
    username = request.form["username-input"]
    password = request.form["password-input"]
    result = main.create_account(username, password)
    if result == 0:
        return flask.redirect("/login")
    elif result == -1:
        flask.flash(u"ERROR: Username or password cannot be blank")
    elif result == -2:
        flask.flash(u"ERROR: Invalid username or password")
        flask.flash(
            u"Usernames and passwords may contain any character except '")
    else:
        flask.flash(u"ERROR: User already exists")
    return flask.redirect("/registration")


@app.route("/help")
def help_page():
    app.logger.debug("Help")
    global CURRENT_CONNECTION
    CURRENT_CONNECTION = ""
    return flask.render_template("help.html")


@app.route("/about")
def about_page():
    app.logger.debug("About")
    global CURRENT_CONNECTION
    CURRENT_CONNECTION = ""
    return flask.render_template("about.html")


@app.route("/contactus")
def contact_us():
    app.logger.debug("Contact us")
    global CURRENT_CONNECTION
    CURRENT_CONNECTION = ""
    return flask.render_template("contactus.html")


@app.route("/index")
def index():
    app.logger.debug("Index")
    messages = get_messages()
    contacts = get_contacts()
    return flask.render_template("p2p.html", contacts=contacts,
                                 contact_length=len(contacts),
                                 messages=messages,
                                 messages_length=len(messages),
                                 username_display=main.USERNAME,
                                 friendcode_display=main.FRIENDCODE,
                                 internal_friendcode_display=main.INTERNAL_FRIENDCODE,
                                 current_message=CURRENT_CONNECTION)


@app.route("/_add_contact", methods=['POST'])
def _add_contact():
    app.logger.debug("Add contact")
    friendcode = request.form['friendcode']
    name = request.form['name']
    if friendcode == "" or name == "":
        flask.flash(u"ERROR: Must specify a name and friendcode for a contact")
        return flask.redirect("/index")
    main.add_contact(name, friendcode)
    main._clear_contact_list()
    main._populate_contact_list(main.USER_ID)
    # messages = get_messages()
    # contacts = get_contacts()
    return flask.redirect("/index")


@app.route("/_message_contact", methods=['POST'])
def _message_contact():
    global CURRENT_RECIPIENT, CURRENT_CONNECTION
    contact_id = request.form["ind"]
    app.logger.debug(f"Messaging contact: {contact_id}")
    CURRENT_RECIPIENT = int(contact_id)
    contacts = get_contacts()
    main._clear_message_list()
    main._populate_message_list(main.USER_ID,
                                contacts[CURRENT_RECIPIENT - 1][0])
    CURRENT_CONNECTION = f"Now messaging: {contacts[CURRENT_RECIPIENT - 1][3]}"
    return flask.redirect("/index")


@app.route("/send_message", methods=['POST'])
def send_message():
    app.logger.debug("Send message")

    # get the text
    text = request.form["text"]

    # update contact list
    main._clear_contact_list()
    main._populate_contact_list(main.USER_ID)

    # get contact list
    contacts = get_contacts()
    print(contacts)

    # get message list
    # messages = get_messages()

    if CURRENT_RECIPIENT == 0:
        flask.flash(u"ERROR: Must specify contact before sending message")
        return flask.redirect("/index")
    elif len(text) > 255:
        flask.flash(u"ERROR: Message cannot be longer than 255 characters")
        return flask.redirect("/index")
    elif len(contacts[CURRENT_RECIPIENT - 1][5]) < 10:
        flask.flash(u"ERROR: Cannot initiate messaging with a contact "
                    u"until an initial key exchange has taken place")
        return flask.redirect("/index")

    # key exchange test
    # maybe add check if this has been done already
    if text == "start_keys":
        app.logger.debug(f"starting the key exchange protocol")
        main.start_keyexchange(contacts[CURRENT_RECIPIENT - 1])
        return flask.redirect("/index")

    # create the message
    message = main.create_message(text, contacts[CURRENT_RECIPIENT - 1])

    # send the message
    result = main.send_message(message, contacts[CURRENT_RECIPIENT - 1])

    if result == 0:
        flask.flash(u"Error: connection failed. Make sure contact is online.")
        return flask.redirect("/index")

    # update message list
    main._clear_message_list()
    main._populate_message_list(main.USER_ID,
                                contacts[CURRENT_RECIPIENT - 1][0])

    return flask.redirect("/index")


@app.route("/key_exchange")
def global_key_exchange():
    if CURRENT_RECIPIENT == 0:
        flask.flash(u"ERROR: No contact selected, "
                    u"cannot initiate key exchange")
        return flask.redirect("/index")
    app.logger.debug("Key exchange")
    contacts = get_contacts()
    main.start_keyexchange(contacts[CURRENT_RECIPIENT - 1])
    return flask.redirect("/index")


@app.route("/clear")
def clear_chat():
    app.logger.debug("Clear")
    global CURRENT_CONNECTION, CURRENT_RECIPIENT
    CURRENT_CONNECTION = ""
    CURRENT_RECIPIENT = 0
    main._clear_message_list()
    return flask.redirect("/index")


@app.errorhandler(404)
def page_not_found(error):
    app.logger.debug("Page not found")
    global CURRENT_CONNECTION
    flask.session['linkback'] = flask.url_for("index")
    CURRENT_CONNECTION = ""
    return flask.render_template('404.html'), 404


def get_contacts():
    return [i for i in main.CONTACT_LIST]


def get_messages():
    main._clear_contact_list()
    main._populate_contact_list(main.USER_ID)
    return [(i[3],
             i[2],
             i[4],
             main.CONTACT_LIST[CURRENT_RECIPIENT - 1][3]) for i in main.MESSAGE_LIST]


if __name__ == '__main__':
    PORT = 5000
    print(f"Opening for global access on port {PORT}")
    app.run(port=PORT, host="0.0.0.0", debug=True, threaded=False)
