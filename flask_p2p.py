"""Flask Backend for the Peer-2-Peer Messaging System.

Functions:



Author:

    Justin Spidell

TODO:

    Add Images (generally spruce up the website)
    Make 404 better
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


@app.route("/")
@app.route("/login")
def login():
    if main.SERVER_THREAD is not None:
        main.SERVER_THREAD.terminate()
        main.SERVER_THREAD = None
    return flask.render_template("login.html")


@app.route("/login_attempt", methods=["POST"])
def login_attempt():
    username = request.form["username-input"]
    password = request.form["password-input"]
    result = main.login(username, password)
    if result == 0:
        if main.SERVER_THREAD is not None:
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
    return flask.render_template("register.html")


@app.route("/registration_attempt", methods=["POST"])
def registration_attempt():
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
    return flask.render_template("help.html")


@app.route("/about")
def about_page():
    return flask.render_template("about.html")


@app.route("/contactus")
def contact_us():
    return flask.render_template("contactus.html")


@app.route("/index")
def index():
    app.logger.debug("Main page entry")
    messages = get_messages()
    contacts = get_contacts()
    return flask.render_template("p2p.html", contacts=contacts,
                                 contact_length=len(contacts),
                                 messages=messages,
                                 messages_length=len(messages),
                                 username_display=main.USERNAME,
                                 friendcode_display=main.FRIENDCODE)


@app.route("/_add_contact", methods=['POST'])
def _add_contact():
    app.logger.debug("Add contact request")
    friendcode = request.form['friendcode']
    name = request.form['name']
    main.add_contact(name, friendcode)
    messages = get_messages()
    contacts = get_contacts()
    return flask.render_template("p2p.html", contacts=contacts,
                                 contact_length=len(contacts),
                                 messages=messages,
                                 messages_length=len(messages),
                                 username_display=main.USERNAME,
                                 friendcode_display=main.FRIENDCODE)


@app.route("/_message_contact", methods=['POST'])
def _message_contact():
    contact_id = request.form["ind"]
    app.logger.debug(f"Messaging contact: {contact_id}")
    CURRENT_RECIPIENT = int(contact_id)
    main._populate_message_list(main.USER_ID, CURRENT_RECIPIENT)
    messages = get_messages()
    contacts = get_contacts()
    return flask.render_template("p2p.html", contacts=contacts,
                                 contact_length=len(contacts),
                                 messages=messages,
                                 messages_length=len(messages),
                                 username_display=main.USERNAME,
                                 friendcode_display=main.FRIENDCODE)


@app.route("/send_message", methods=['POST'])
def send_message():

    # get the text
    text = request.form["text"]
    app.logger.debug(f"text to send: {text}")

    # get contact list
    contacts = get_contacts()
    app.logger.debug(f"contacts: {contacts}")

    # get message list
    messages = get_messages()
    app.logger.debug(f"messages: {messages}")

    # key exchange test
    # maybe add check if this has been done already
    if text == "start_keys":
        app.logger.debug(f"starting the key exchange protocol")
        main.start_keyexchange(contacts[CURRENT_RECIPIENT])
        return flask.render_template("p2p.html", contacts=contacts,
                                 contact_length=len(contacts),
                                 messages=messages,
                                 messages_length=len(messages),
                                 username_display=main.USERNAME,
                                 friendcode_display=main.FRIENDCODE)

    # create the message
    message = main.create_message(text, contacts[CURRENT_RECIPIENT])
    app.logger.debug(f"message: {message}")

    # send the message
    main.send_message(message, contacts[CURRENT_RECIPIENT])

    return flask.render_template("p2p.html", contacts=contacts,
                                 contact_length=len(contacts),
                                 messages=messages,
                                 messages_length=len(messages),
                                 username_display=main.USERNAME,
                                 friendcode_display=main.FRIENDCODE)


@app.errorhandler(404)
def page_not_found(error):
    app.logger.debug("Page not found")
    flask.session['linkback'] = flask.url_for("index")
    return flask.render_template('404.html'), 404


def get_contacts():
    #return [(i[3], i[0]) for i in main.CONTACT_LIST]
    return [i for i in main.CONTACT_LIST]


def get_messages():
    return [(i[3], i[2]) for i in main.MESSAGE_LIST]


if __name__ == '__main__':
    PORT = 5000
    print(f"Opening for global access on port {PORT}")
    # server_thread = threading.Thread(target=main.start_server, args=[])
    # server_thread.start()
    app.run(port=PORT, host="0.0.0.0", debug=True, threaded=False)
