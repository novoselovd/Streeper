import os
from flask import Flask, render_template, url_for, redirect, flash
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SelectField, validators, IntegerField, SelectMultipleField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from generator import getrandompassword
from channel_info import ChannelInfo


app = Flask(__name__)
Bootstrap(app)

db_path = os.path.join(os.path.dirname(__file__), 'users.db')
channels_path = os.path.join(os.path.dirname(__file__), 'channels.db')
db_uri = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_BINDS'] = {'channels': 'sqlite:///{}'.format(channels_path)}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = '2fHGGFdePK'
app.config.from_pyfile('config.cfg')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


#Mail_settings
mail = Mail(app)
s = URLSafeTimedSerializer('giax5RHYLB')


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(80))
    type = db.Column(db.String(30))
    email_confirmed = db.Column(db.Boolean(), default=0)
    current_balance = db.Column(db.Float(), default=0)


class Channel(db.Model):
    __bind_key__ = 'channels'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String)
    link = db.Column(db.String(50))
    description = db.Column(db.String(200))
    subscribers = db.Column(db.Integer)
    price = db.Column(db.Integer)
    category = db.Column(db.String(50))
    image = db.Column(db.String)
    admin_id = db.Column(db.Integer, db.ForeignKey(User.id))


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
    link = StringField('Channel link', [InputRequired(), Length(min=1, max=50)])
    name = StringField('Channel name')
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
    category = SelectField('Category', choices=category_choices)
    description = StringField('Channel description', [InputRequired(), Length(max=200)])
    subscribers = IntegerField('Number of subscribers')
    price = IntegerField('Price', validators=[InputRequired()])


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current password', validators=[InputRequired()])
    new_password = PasswordField('New password', validators=[InputRequired(),
                                                             validators.EqualTo('new_password_confirm', message='Passwords do not match.')])
    new_password_confirm = PasswordField('Confirm new password', validators=[InputRequired()])


#Сделал формой, но хз, наверно не имело смысла
class ResetForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(message='Incorrect email.'), Length(max=50)])


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

        #Отправка письма
        token = s.dumps(form.email.data, salt='email-confirm')
        msg = Message('Confirm Email', sender='ouramazingapp@gmail.com', recipients=[form.email.data])

        link = url_for('confirm_email', token=token, _external=True)
        msg.body = 'Your link is {}'.format(link)

        mail.send(msg)

        flash("Success! Now you can log in.")
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


#TODO: доделать добавление площадки


@app.route('/add_marketplace', methods=['GET', 'Post'])
@login_required
def add_marketplace():
    if current_user.type != 'Brand/Agency':
        flash('You cannot add a channel because of your account type!')
        return redirect(url_for('marketplace'))
    form = CreateChannelForm()
    if form.validate_on_submit():
        if Channel.query.filter_by(link=(form.link.data).lower()).first():
            flash('Such marketplace already exists')
            return redirect(url_for('add_marketplace'))
        try:
            # some magic with api inside ChannelInfo object
            ci = ChannelInfo(form.link.data)
            form.name.data = ci.name
            new_channel = Channel(name=ci.name,
                                  link=form.link.data, description=form.description.data,
                                  subscribers=ci.subscribers,
                                  price=form.price.data, category=form.category.data,
                                  image=ci.photo, admin_id=current_user.id)

            db.session.add(new_channel)
            db.session.commit()

            flash('Great! Your channel "%s" successfully added!' % new_channel.name)

            return redirect(url_for('marketplace'))
        except NameError:
            flash('No such channel found or incorrect link given')
            return redirect(url_for('add_marketplace'))

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


# @app.route('/contact')
# def contact():
#     return render_template('contact.html')


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(current_user.password, form.current_password.data):
            new_hashed_password = generate_password_hash(form.new_password.data, method='sha256')

            curr = User.query.filter_by(email=current_user.email).first()
            curr.password = new_hashed_password

            db.session.commit()
            flash('Successfully updated your password')
            return redirect(url_for('settings'))
        else:
            flash('Current password is wrong')
            return redirect(url_for('settings'))
    return render_template('settings.html', form=form)


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        curr = User.query.filter_by(email=email).first()
        curr.email_confirmed = 1
        db.session.commit()
    except SignatureExpired:
        return '<h1>The confirmation link has expired...</h1>'
    return render_template('confirm_email.html')


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if current_user.is_authenticated:
        return redirect(url_for('/'))
    form = ResetForm()
    if form.validate_on_submit():
        if not User.query.filter_by(email=form.email.data.lower()).first():
            flash("User with email you entered not found!")
            return redirect(url_for('reset'))
        else:
            new_password = getrandompassword()
            curr = User.query.filter_by(email=form.email.data.lower()).first()
            curr.password = generate_password_hash(new_password, method='sha256')
            db.session.commit()

            msg = Message('Password reset', sender='ouramazingapp@gmail.com', recipients=[form.email.data])
            msg.html = 'Your new password is <b>{}</b>, you can change it in account settings'.format(new_password)
            mail.send(msg)

            flash("Check your email for further instructions")
            return redirect(url_for('reset'))

    return render_template('reset.html', form=form)


if __name__ == '__main__':
    app.run(debug=True)