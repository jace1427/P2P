"""Flask Backend for the Peer-2-Peer Messaging System.

Functions:

    index

Author:

    Justin Spidell

TODO:

    Add Images (generally spruce up the website)
    Make 404 better
"""
import flask
from flask import request
import main

app = flask.Flask(__name__)
app.secret_key = bytes(1)


@app.route("/")
@app.route("/login")
def login():
    return flask.render_template("login.html")


@app.route("/login_attempt", methods=["POST"])
def login_attempt():
    username = request.form["username-input"]
    password = request.form["password-input"]
    app.logger.debug(username)
    app.logger.debug(password)
    result = main.login(username, password)
    if result == 0:
        return flask.redirect("/index")
    elif result == -1:
        flask.flash(u"ERROR: Username or password cannot be blank")
    elif result == -2:
        flask.flash(u"ERROR: Invalid username or password")
        flask.flash(
            u"Usernames and passwords may contain any character except '")
    else:
        flask.flash(u"ERROR: User not found")
    return flask.redirect("/login")


@app.route("/registration")
def registration():
    return flask.render_template("register.html")


@app.route("/registration_attempt", methods=["POST"])
def registration_attempt():
    username = request.form["username-input"]
    password = request.form["password-input"]
    app.logger.debug(username)
    app.logger.debug(password)
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
    contacts = get_contacts()
    return flask.render_template("p2p.html", contacts=contacts,
                                 contact_length=len(contacts))


@app.route("/_add_contact", methods=['POST'])
def _add_contact():
    app.logger.debug("Add contact request")
    app.logger.debug(request.form)
    contacts = get_contacts()
    return flask.render_template("p2p.html", contacts=contacts,
                                 contact_length=len(contacts))


@app.route("/_message_contact", methods=['POST'])
def _message_contact():
    app.logger.debug("Message contact")
    app.logger.debug(request.form)
    contacts = get_contacts()
    return flask.render_template("p2p.html", contacts=contacts,
                                 contact_length=len(contacts))


@app.errorhandler(404)
def page_not_found(error):
    app.logger.debug("Page not found")
    flask.session['linkback'] = flask.url_for("index")
    return flask.render_template('404.html'), 404


def get_contacts():
    return [(i[3], i[2]) for i in main.CONTACT_LIST]


if __name__ == '__main__':
    PORT = 5000
    print(f"Opening for global access on port {PORT}")
    app.run(port=PORT, host="0.0.0.0", debug=True, threaded=False)
