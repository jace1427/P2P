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

app = flask.Flask(__name__)
app.secret_key = bytes(1)


@app.route("/")
@app.route("/index")
def index():
    app.logger.debug("Main page entry")
    return flask.render_template("p2p.html")


@app.route("/message")
def message():
    app.logger.debug("Message entry")
    return flask.render_template("message.html")


@app.errorhandler(404)
def page_not_found(error):
    app.logger.debug("Page not found")
    flask.session['linkback'] = flask.url_for("index")
    return flask.render_template('404.html'), 404


if __name__ == '__main__':
    PORT = 5000
    print(f"Opening for global access on port {PORT}")
    app.run(port=PORT, host="0.0.0.0", debug=True)
