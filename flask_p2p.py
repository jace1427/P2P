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
# from flask import request

app = flask.Flask(__name__)
app.secret_key = bytes(1)

@app.route("/")
@app.route("/login")
def login():
    return flask.render_template("login.html")

@app.route("/registration")
def registration():
    return flask.render_template("register.html")

@app.route("/help")
def help_page():
    return flask.render_template("help.html")

@app.route("/about")
def about_page():
    return flask.render_template("about.html")

@app.route("/contactus")
def contact_us():
    return flask.render_template("contactus.html")

# @app.route("/")
@app.route("/index", methods=['POST'])
def index():
    app.logger.debug(request.form)
    app.logger.debug("Main page entry")
    return flask.render_template("p2p.html")


@app.errorhandler(404)
def page_not_found(error):
    app.logger.debug("Page not found")
    flask.session['linkback'] = flask.url_for("index")
    return flask.render_template('404.html'), 404


@app.route("/send", methods=['POST'])
def send():
    app.logger.debug(request.form)
    flask.flash(u"ERROR: Please submit a distance", "error")
    return flask.render_template('404.html'), 404


if __name__ == '__main__':
    PORT = 5000
    print(f"Opening for global access on port {PORT}")
    app.run(port=PORT, host="0.0.0.0", debug=True)
