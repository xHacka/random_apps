from flask_sqlalchemy import SQLAlchemy

MAX_SIZE = 2**16 - 1  # 65535

db = SQLAlchemy()


class Decoded(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(MAX_SIZE), nullable=False)


class Encoded(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(MAX_SIZE), nullable=False)


def save_item(db, table, **data):
    item = table(**data)
    db.session.add(item)
    db.session.commit()
