from flask_login import UserMixin

from app import db


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    type = db.Column(db.String(30))
    email_confirmed = db.Column(db.Boolean(), default=0)
    current_balance = db.Column(db.Float(), default=0)
    channels = db.relationship('Channel', backref='admin', lazy='dynamic')


class Channel(db.Model):
    __bind_key__ = 'channels'
    id = db.Column(db.Integer, primary_key=True)
    link = db.Column(db.String(50))
    name = db.Column(db.String(50))
    description = db.Column(db.String(200))
    subscribers = db.Column(db.Integer)
    price = db.Column(db.Integer)
    secret = db.Column(db.String)
    confirmed = db.Column(db.Boolean(), default=0)
    category = db.Column(db.String(50))
    image = db.Column(db.String)
    admin_id = db.Column(db.Integer, db.ForeignKey(User.id))