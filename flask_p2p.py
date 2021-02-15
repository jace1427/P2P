"""

"""
import flask

app = flask.Flask(__name__)


@app.route("/")
@app.route("/index")
def index():
    app.logger.debug("main page entry")
    return flask.render_template('main.html')


if __name__ == '__main__':
    PORT = 5000
    print(f"Opening for global access on port {PORT}")
    app.run(port=PORT, host="0.0.0.0", debug=True)
