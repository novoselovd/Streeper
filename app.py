import os
from flask import Flask, render_template, url_for, redirect, flash
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm, Form
from wtforms import StringField, PasswordField, BooleanField, SelectField, validators, IntegerField, SelectMultipleField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
Bootstrap(app)

db_path = os.path.join(os.path.dirname(__file__), 'users.db')
channels_path = os.path.join(os.path.dirname(__file__), 'channels.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_BINDS'] = {'channels': 'sqlite:///{}'.format(channels_path)}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = '2fHGGFdePK'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    type = db.Column(db.String(30))


class Channel(db.Model):
    __bind_key__ = 'channels'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    description = db.Column(db.String(200))
    subscribers = db.Column(db.Integer)
    price = db.Column(db.Integer)
    category = db.Column(db.String(50))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Incorrect email.'), Length(max=50)])
    password = PasswordField('Password', validators=[InputRequired()])
    remember = BooleanField('Remember me')


class RegisterForm(FlaskForm):
    name = StringField('Name', [InputRequired(), Length(min=1, max=50)])
    email = StringField('Email', validators=[InputRequired(), Email(message='Incorrect email.'), Length(max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match.')
    ])
    confirm = PasswordField('Confirm Password')
    type = SelectField('Account type',
                       choices=[('Brand/Agency', 'Brand/Agency'), ('Creator/Influencer', 'Creator/Influencer')])
    tos = BooleanField('I agree to <a href="/tos">Terms of Service</a>', validators=[validators.DataRequired()])


class CreateChannelForm(FlaskForm):
    name = StringField('Channel', [InputRequired(), Length(min=1, max=50)])
    category_choices = [('cars', 'cars'), ('business', 'business'),
                        ('realty', 'realty'), ('medicine and health', 'medicine and health'),
                        ('marketing', 'marketing'), ('work', 'work'),
                        ('travelling', 'travelling'), ('for women', 'for women'),
                        ('sport', 'sport'), ('culture', 'culture'),
                        ('education', 'education'), ('products and services', 'products and services'),
                        ('18+', '18+'), ('design and decor', 'design and decor'),
                        ('games', 'games'), ('entertainment', 'entertainment'),
                        ('media', 'media'), ('science and technology', 'science and technology'),
                        ('culinary', 'culinary'), ('foreign languages', 'foreign languages'),
                        ('motivation and self-education', 'motivation and self-education'),
                        ('music', 'music'), ('cinematography', 'cinematography'),
                        ('top', 'top')]
    category = SelectField('Keys', choices=category_choices)
    description = StringField('Channel description', [Length(max=200)])
    subscribers = IntegerField('Number of subscribers')
    price = IntegerField('Price', validators=[InputRequired()])


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('marketplace'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=(form.email.data).lower()).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('marketplace'))

        flash("Invalid email or/and password!")
        return redirect(url_for('login'))

    return render_template('login.html', form=form)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('marketplace'))

    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(email=(form.email.data).lower()).first():
            flash("User already exists!")
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(name=form.name.data, email=(form.email.data).lower(), password=hashed_password,
                        type=form.type.data)
        db.session.add(new_user)
        db.session.commit()

        flash("Success! Now you can log in.")
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


@app.route('/add_marketplace', methods=['GET', 'POST'])
@login_required
def add_marketplace():
    print(current_user.type)
    if 'Brand/Agency' != current_user.type:
        # flash('You can not access this page')
        return redirect(url_for('marketplace'))
    form = CreateChannelForm()
    if form.validate_on_submit():
        if Channel.query.filter_by(name=(form.name.data).lower()).first():
            flash('Such marketplace already exists')
            return redirect(url_for('marketplace'))
        new_channel = Channel(name=form.name.data, description=form.description.data,
                              subscribers=form.subscribers.data,
                              price=form.price.data, category=form.category.data)
        flash('Great! Your channel "%s" successfully added!' % new_channel.name)

        db.session.add(new_channel)
        db.session.commit()
    return render_template('add_marketplace.html', form=form)


@app.route('/marketplace')
@login_required
def marketplace():
    return render_template('marketplace.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/tos')
def tos():
    return render_template('tos.html')


@app.route('/privacy')
def privacy():
    return render_template('privacy.html')


@app.route('/contact')
def contact():
    return render_template('contact.html')


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')


if __name__ == '__main__':
    app.run(debug=True)