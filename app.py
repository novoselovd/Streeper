import os
import models
import requests
from flask import Flask, render_template, url_for, redirect, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from forms import LoginForm, RegisterForm, CreateChannelForm, ChangePasswordForm, ResetForm
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


import models


#Mail_settings
mail = Mail(app)
s = URLSafeTimedSerializer('giax5RHYLB')


@login_manager.user_loader
def load_user(user_id):
    return models.User.query.get(int(user_id))


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('marketplace'))

    form = LoginForm()
    if form.validate_on_submit():
        user = models.User.query.filter_by(email=(form.email.data).lower()).first()
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
        if models.User.query.filter_by(email=(form.email.data).lower()).first():
            flash("User already exists!")
            return redirect(url_for('signup'))
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = models.User(name=form.name.data, email=(form.email.data).lower(), password=hashed_password,
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


@app.route('/add_marketplace', methods=['GET', 'Post'])
@login_required
def add_marketplace():
    if current_user.type != 'Brand/Agency':
        flash('You cannot add a channel because of your account type!')
        return redirect(url_for('marketplace'))
    form = CreateChannelForm()
    if form.validate_on_submit():
        if models.Channel.query.filter_by(link=(form.link.data).lower()).first():
            flash('Such marketplace already exists')
            return redirect(url_for('add_marketplace'))
        try:
            # some magic with api inside ChannelInfo object
            ci = ChannelInfo(form.link.data)
            form.name.data = ci.name
            new_channel = models.Channel(name=ci.name,
                                  link=ci.chat_id, description=form.description.data,
                                  subscribers=ci.subscribers,
                                  price=form.price.data, secret=getrandompassword(), category=form.category.data,
                                  image=ci.photo, admin_id=current_user.id)

            db.session.add(new_channel)
            db.session.commit()

            flash('Great! Now you can confirm ownership in account settings section')

            return redirect(url_for('marketplace'))
        except NameError:
            flash('No such channel found or incorrect link given')
            return redirect(url_for('add_marketplace'))

    return render_template('add_marketplace.html', form=form)


@app.route('/marketplace', methods=['GET', 'POST'])
@login_required
def marketplace():
    channels = models.Channel.query.filter(models.Channel.confirmed == 1)
    if request.method == 'POST':
        category = request.form['sel']
        price = request.form['pf'].split(',')
        subscribers = request.form['sf'].split(',')
        if category.lower() == 'all':
            channels = models.Channel.query.filter(models.Channel.price >= price[0]).\
                filter(models.Channel.price <= price[1]).\
                filter(models.Channel.subscribers >= subscribers[0]).\
                filter(models.Channel.subscribers <= subscribers[1]).\
                filter(models.Channel.confirmed == 1)

            return render_template('marketplace.html', channels=channels, curr_cat=category, curr_price=price,
                           curr_subs=subscribers)
        else:
            channels = models.Channel.query.filter(models.Channel.price >= price[0]). \
                filter(models.Channel.price <= price[1]). \
                filter(models.Channel.subscribers >= subscribers[0]). \
                filter(models.Channel.subscribers <= subscribers[1]). \
                filter(models.Channel.category == category.lower()). \
                filter(models.Channel.confirmed == 1)

            return render_template('marketplace.html', channels=channels, curr_cat=category, curr_price=price,
                           curr_subs=subscribers)

    return render_template('marketplace.html', channels=channels, curr_cat='All', curr_price=[10, 10000],
                           curr_subs=[0, 300000])


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
    ab = LoginForm()
    return render_template('contact.html', q=ab)


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    channels = models.Channel.query.filter(models.Channel.admin_id == current_user.id)
    form = ChangePasswordForm()

    if form.validate_on_submit():
        if check_password_hash(current_user.password, form.current_password.data):
            new_hashed_password = generate_password_hash(form.new_password.data, method='sha256')

            curr = models.User.query.filter_by(email=current_user.email).first()
            curr.password = new_hashed_password

            db.session.commit()
            flash('Successfully updated your password')
            return redirect(url_for('settings'))
        else:
            flash('Current password is wrong')
            return redirect(url_for('settings'))
    # elif request.method == 'POST':
    #     print('gay')
    #     return redirect('/')

    return render_template('settings.html', form=form, channels=channels)


@app.route('/confirm_channel', methods=['POST', 'GET'])
@login_required
def confirm_channel():
    secret = request.args.get('secret')
    channel = models.Channel.query.filter(models.Channel.secret == secret)
    if channel:
        r = requests.get(
            'https://api.telegram.org/bot435931033:AAHtZUDlQ0DeQVUGNIGpTFhcV1u3wXDjKJY/getChat?chat_id=%s'
            % channel[0].link)
        if not r.json()['ok']:
            flash('Something went wrong')
            return redirect('/settings')
        else:
            response = r.json()['result']['description']
            if secret in response:
                ch = models.Channel.query.filter_by(secret=secret).first()
                test = db.session.query(models.Channel).filter_by(secret=secret).first()
                test.confirmed = 1
                db.session.commit()
                flash('Successfully added your channel into our base!')
                return redirect('/marketplace')
            else:
                flash('Could not find the secret key')
                return redirect('/settings')
    else:
        abort(404)



@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
        curr = models.User.query.filter_by(email=email).first()
        curr.email_confirmed = 1
        db.session.commit()
    except SignatureExpired:
        return '<h1>The confirmation link has expired...</h1>'
    return render_template('confirm_email.html')


@app.route('/channel/<r>')
@login_required
def channel(r):
    chan = models.Channel.query.filter_by(link='@'+r).first()
    if not chan:
        abort(404)
    return render_template('channel.html', chan=chan)


# def confirm_ownership():
#     if request.method == 'POST':
#         category = request.form['test']
#         print(category)
#     return redirect('/settings')


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    if current_user.is_authenticated:
        return redirect(url_for('/'))
    form = ResetForm()
    if form.validate_on_submit():
        if not models.User.query.filter_by(email=form.email.data.lower()).first():
            flash("User with email you entered not found!")
            return redirect(url_for('reset'))
        else:
            new_password = getrandompassword()
            curr = models.User.query.filter_by(email=form.email.data.lower()).first()
            curr.password = generate_password_hash(new_password, method='sha256')
            db.session.commit()

            msg = Message('Password reset', sender='ouramazingapp@gmail.com', recipients=[form.email.data])
            msg.html = 'Your new password is <b>{}</b>, you can change it in account settings'.format(new_password)
            mail.send(msg)

            flash("Check your email for further instructions")
            return redirect(url_for('reset'))

    return render_template('reset.html', form=form)


if __name__ == '__main__':
    # update.run()
    app.run(debug=True)
