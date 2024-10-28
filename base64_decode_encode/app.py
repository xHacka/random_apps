from flask import Flask, render_template
from base64 import b64decode, b64encode
from database import db, Encoded, Decoded, save_item
from utils import get_data, get_response, require_data

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///responses.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db.init_app(app)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/d", methods=["POST"])
@require_data
def decode():
    try:
        data = get_data()
        data += "=" * (-len(data) % 4)  # Adjust padding
        data = b64decode(data).decode()
        status = 200

        save_item(db, Decoded, data=data)

    except AttributeError:
        data = "Error: failed to decode given base64"
        status = 400

    return get_response(data, status)


@app.route("/e", methods=["POST"])
@require_data
def encode():
    try:
        data = b64encode(get_data().encode()).decode()
        status = 200

        save_item(db, Encoded, data=data)

    except AttributeError:
        data = "Error: failed to encode given string"
        status = 400

    return get_response(data, status)

@app.route('/ds')
def decode_show():
    records = Decoded.query.all()
    return render_template('table.html', title="Decoded Records", records=records)

@app.route('/es')
def encode_show():
    records = Encoded.query.all()
    return render_template('table.html', title="Encoded Records", records=records)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Create tables

    app.run(host="0.0.0.0", port=8001, debug=False)
