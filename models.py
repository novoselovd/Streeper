from flask_login import UserMixin
from pytz import timezone
from datetime import datetime

UTC = timezone('UTC')


def time_now():
    return datetime.now(UTC)

from app import db



class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    type = db.Column(db.String(30))
    email_confirmed = db.Column(db.Boolean(), default=0)
    current_balance = db.Column(db.Float(), default=0)
    # related with user's channels
    channels = db.relationship('Channel', backref='admin', lazy='dynamic')
    posts = db.relationship('Post', backref='brand', lazy='dynamic')
    withdrawals = db.relationship('Withdrawal', backref='hz', lazy='dynamic')


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
    # channel's owner
    admin_id = db.Column(db.Integer, db.ForeignKey(User.id))
    # related with posts of ads
    requests = db.relationship('Post', backref='channel', lazy='dynamic')


class Post(db.Model):
    __bind_key__ = 'posts'
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(1000))
    link = db.Column(db.String(50))
    comment = db.Column(db.String(1000))
    # if confirmed -> accepted; if !confirmed & !declined -> under consideration; if declined -> declined
    confirmed = db.Column(db.Boolean(), default=0)
    declined = db.Column(db.Boolean(), default=0)
    posted = db.Column(db.Boolean, default=0)
    SHARELINK = db.Column(db.String(50))
    # need to be on channel till that moment
    post_time = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    # post's target channel
    channel_id = db.Column(db.Integer, db.ForeignKey(Channel.id))
    # post's creator
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))


class Withdrawal(db.Model):
    __bind_key__ = 'withdrawals'
    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(1000))
    amount = db.Column(db.Integer)
    card = db.Column(db.Integer)
    date = db.Column(db.TIMESTAMP,  default=time_now)
    user_id = db.Column(db.Integer, db.ForeignKey(User.id))
