import os
import numbers
from flask import Flask, render_template, url_for, redirect, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired

from forms import LoginForm, RegisterForm, CreateChannelForm, ChangePasswordForm, ResetForm, CreatePostForm, \
    TopUpBalanceForm, WithdrawalForm
from generator import getrandompassword
from channel_info import ChannelInfo
import update
import models
import stripe
import requests
from lxml import html


app = Flask(__name__)
Bootstrap(app)

db_path = os.path.join(os.path.dirname(__file__), 'users.db')
channels_path = os.path.join(os.path.dirname(__file__), 'channels.db')
posts_path = os.path.join(os.path.dirname(__file__), 'posts.db')
withdrawals_path = os.path.join(os.path.dirname(__file__), 'withdrawals.db')

db_uri = 'sqlite:///{}'.format(db_path)
app.config['SQLALCHEMY_DATABASE_URI'] = db_uri
app.config['SQLALCHEMY_BINDS'] = {'channels': 'sqlite:///{}'.format(channels_path),
                                  'posts': 'sqlite:///{}'.format(posts_path),
                                  'withdrawals': 'sqlite:///{}'.format(withdrawals_path)}
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SECRET_KEY'] = '2fHGGFdePK'
app.config.from_pyfile('config.cfg')

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Mail_settings
mail = Mail(app)
s = URLSafeTimedSerializer('giax5RHYLB')

# stripe keys
pub_key = 'pk_test_rW2nCw0ukmmWD7KWQwIzWOlW'
secret_key = 'sk_test_mqlBWdwuEV2Dm69ymxOIDwtg'
stripe.api_key = secret_key


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

        # letter sending
        token = s.dumps(form.email.data, salt='email-confirm')
        msg = Message('Confirm Email', sender='ouramazingapp@gmail.com', recipients=[form.email.data])

        link = url_for('confirm_email', token=token, _external=True)
        msg.body = 'Your link is {}'.format(link)

        mail.send(msg)

        flash("Success! Now you can log in.")
        return redirect(url_for('login'))

    return render_template('signup.html', form=form)


@app.route('/add_channel', methods=['GET', 'Post'])
@login_required
def add_channel():
    if current_user.type != 'Brand/Agency':
        flash('You cannot add a channel if don\'t have one!')
        return redirect(url_for('marketplace'))
    form = CreateChannelForm()
    if form.validate_on_submit():
        try:
            # some magic with api inside ChannelInfo object
            ci = ChannelInfo(form.link.data)
            if models.Channel.query.filter_by(link=form.link.data.lower()).first():
                flash('Such marketplace already exists')
                return redirect(url_for('add_channel'))
            form.name.data = ci.name
            new_channel = models.Channel(name=ci.name,
                                         link=ci.chat_id, description=form.description.data,
                                         subscribers=ci.subscribers,
                                         price=form.price.data, secret=getrandompassword(),
                                         category=form.category.data,
                                         image=ci.photo, admin_id=current_user.id)
            flash('Great! Now you can confirm ownership in account settings section.')

            db.session.add(new_channel)
            db.session.commit()
            return redirect(url_for('marketplace'))
        except NameError:
            flash('No such channel found or incorrect link given')
            return redirect(url_for('add_channel'))

    return render_template('add_channel.html', form=form)


@app.route('/marketplace', methods=['GET', 'POST'])
@login_required
def marketplace():
    channels = models.Channel.query.filter(models.Channel.confirmed == 1)
    if request.method == 'POST':
        category = request.form['sel']
        price = request.form['pf'].split(',')
        subscribers = request.form['sf'].split(',')
        if category.lower() == 'all':
            channels = models.Channel.query.filter(models.Channel.price >= price[0]). \
                filter(models.Channel.price <= price[1]). \
                filter(models.Channel.subscribers >= subscribers[0]). \
                filter(models.Channel.subscribers <= subscribers[1]). \
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


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        subject = request.form['subject']
        email = request.form['email']
        message = request.form['message']

        msg = Message(subject, sender='ouramazingapp@gmail.com', recipients=["tbago@yandex.ru"])
        msg.body = message + " {}".format(email)
        mail.send(msg)

        flash("Thank you :) We will respond to your question as soon as we can")
        return redirect('/contact')
    return render_template('contact.html')


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    channels = models.Channel.query.filter(models.Channel.admin_id == current_user.id)

    req = 0

    for i in current_user.channels.all():
        for j in i.requests.all():
            req += 1


    tu = TopUpBalanceForm()

    form = ChangePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(current_user.password, form.current_password.data):
            new_hashed_password = generate_password_hash(form.new_password.data, method='sha256')

            curr = db.session.query(models.User).filter_by(email=current_user.email).first()
            curr.password = new_hashed_password

            db.session.commit()
            flash('Successfully updated your password')
            return redirect(url_for('settings'))
        else:
            flash('Current password is wrong')
            return redirect(url_for('settings'))

    if tu.validate_on_submit() and request.method == 'POST':
        customer = stripe.Customer.create(email=request.form['stripeEmail'],
                                          source=request.form['stripeToken'])
        charge = stripe.Charge.create(
            customer=customer,
            amount=tu.amount.data,
            currency='usd',
            description='Posting'
        )

        curr = db.session.query(models.User).filter_by(email=current_user.email).first()
        curr.current_balance = curr.current_balance + form.amount.data

        db.session.commit()

        flash('Successfully replenished your balance!')
        return redirect('/settings')


    return render_template('settings.html', form=form, channels=channels, user=current_user, req=req, tu=tu)


@app.route('/user/<uniqid>', methods=['GET', 'POST'])
@login_required
def user(uniqid):
    if str(current_user.id) != uniqid:
        abort(404)
    curr = db.session.query(models.User).filter_by(email=current_user.email).first()
    if curr is None:
        flash('User\'s id ' + uniqid + ' not found.')
        return redirect(url_for('index'))

    return render_template('user.html',
                           user=curr,
                           )


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
                ch = db.session.query(models.Channel).filter_by(secret=secret).first()
                ch.confirmed = 1
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
        curr = db.session.query(models.User).filter_by(email=email).first()
        curr.email_confirmed = 1
        db.session.commit()
    except SignatureExpired:
        return '<h1>The confirmation link has expired...</h1>'
    return render_template('confirm_email.html')


@app.route('/delete_channel', methods=['POST', 'GET'])
@login_required
def delete_channel():
    secret = request.args.get('secret')
    ch = db.session.query(models.Channel).filter_by(secret=secret).first()
    if current_user.id == ch.admin_id:
        db.session.delete(ch)
        db.session.commit()

        flash('Successfully deleted channel from database!')
        return redirect('/settings')
    else:
        flash('Ooops, something went wrong!')
        return redirect('/settings')


@app.route('/channel/<r>', methods=['GET', 'POST'])
@login_required
def channel(r):
    chan = models.Channel.query.filter_by(link='@' + r).first()
    if not chan:
        abort(404)
    form = CreatePostForm()
    if form.validate_on_submit():
        if current_user.current_balance < chan.price:
            flash("You do not have enough funds to advertise here")
            return redirect("/channel/" + r)
        post = models.Post(content=form.content.data,
                           link=form.link.data,
                           comment=form.comment.data,
                           channel_id=chan.id,
                           user_id=current_user.id)
        db.session.add(post)
        db.session.commit()

        user = db.session.query(models.User).filter_by(email=current_user.email).first()
        user.current_balance -= chan.price
        db.session.commit()


        flash('Great! Your request successfully sent to "%s"\'s administrator!' % chan.name)
        return redirect(url_for('marketplace'))
    return render_template('channel.html', chan=chan, form=form)


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
            curr = db.session.query(models.User).filter_by(email=form.email.data.lower()).first()
            curr.password = generate_password_hash(new_password, method='sha256')
            db.session.commit()

            msg = Message('Password reset', sender='ouramazingapp@gmail.com', recipients=[form.email.data])
            msg.html = 'Your new password is <b>{}</b>, you can change it in account settings'.format(new_password)
            mail.send(msg)

            flash("Check your email for further instructions")
            return redirect(url_for('reset'))

    return render_template('reset.html', form=form)


@app.route('/withdrawal', methods=['GET', 'POST'])
@login_required
def withdrawal():
    form = WithdrawalForm()

    w = models.Withdrawal.query.filter_by(user_id=current_user.id)

    if form.validate_on_submit():
        if current_user.current_balance < form.amount.data:
            flash('You do not have enough funds')
            return redirect('/withdrawal')
        else:
            user = db.session.query(models.User).filter_by(email=current_user.email).first()
            user.current_balance -= form.amount.data
            db.session.commit()

            new_withdrawal = models.Withdrawal(status="Request sent", amount=form.amount.data, card=form.card.data, user_id=current_user.id)
            db.session.add(new_withdrawal)
            db.session.commit()

            msg = Message('Withdrawal request', sender='ouramazingapp@gmail.com', recipients=["tbago@yandex.ru"])
            msg.body = 'User ' + current_user.email + ' wants ' + str(form.amount.data) + ' dollars on ' + str(form.card.data)
            mail.send(msg)

            flash('Your request was successfully sent')
            return redirect('/withdrawal')
    return render_template('withdrawal.html', form=form, w=w)


@app.route('/accept_request', methods=['POST', 'GET'])
@login_required
def accept_request():
    request_post = db.session.query(models.Post).filter_by(id=int(request.args.get('request_id'))).first()
    request_post.confirmed = True
    db.session.commit()
    flash('Great! You now have to confirm your posting via ad post\'s SHARE LINK!')
    return redirect('/user/%s' % current_user.id)


@app.route('/decline_request', methods=['POST', 'GET'])
@login_required
def decline_request():
    request_post = db.session.query(models.Post).filter_by(id=int(request.args.get('request_id'))).first()
    request_post.declined = 1
    db.session.commit()

    userForCashback = db.session.query(models.User).filter_by(id=request_post.user_id).first()
    chan = db.session.query(models.Channel).filter_by(id=request_post.channel_id).first()
    userForCashback.current_balance += chan.price
    db.session.commit()

    flash('Got rid of that one!')
    return redirect('/user/%s' % current_user.id)


@app.route('/rollback', methods=['POST', 'GET'])
@login_required
def rollback():
    request_post = db.session.query(models.Post).filter_by(id=int(request.args.get('post_id'))).first()
    db.session.delete(request_post)
    db.session.commit()

    userForCashback = db.session.query(models.User).filter_by(id=request_post.user_id).first()
    chan = db.session.query(models.Channel).filter_by(id=request_post.channel_id).first()
    userForCashback.current_balance += chan.price
    db.session.commit()

    flash('Great! Successfully canceled your request!')
    return redirect('/user/%s' % current_user.id)


@app.route('/switch_channel', methods=['POST', 'GET'])
@login_required
def switch_channel():
    request_post = db.session.query(models.Post).filter_by(id=int(request.args.get('post_id'))).first()
    return redirect('/user/%s' % current_user.id)


@app.route('/remove_row', methods=['POST', 'GET'])
@login_required
def remove_row():
    request_post = db.session.query(models.Post).filter_by(id=int(request.args.get('post_id'))).first()
    db.session.delete(request_post)
    db.session.commit()
    return redirect('/user/%s' % current_user.id)


@app.route('/addfunds', methods=['GET', 'POST'])
@login_required
def addfunds():
    if current_user.type == "Brand/Agency":
        abort(404)
    form = TopUpBalanceForm()
    curr = db.session.query(models.User).filter_by(email=current_user.email).first()

    if form.validate_on_submit() and request.method == 'POST':

        if isinstance(form.amount.data, int) and form.amount.data > 1:
            customer = stripe.Customer.create(email=request.form['stripeEmail'],
                                              source=request.form['stripeToken'])
            charge = stripe.Charge.create(
                customer=customer,
                amount=form.amount.data*100,
                currency='usd',
                description='Posting'
            )

            curr.current_balance = curr.current_balance + form.amount.data
            db.session.commit()

            flash('Successfully replenished your balance!')
            return redirect('/settings')
        else:
            flash('Ooops...Something went wrong')
            return redirect('/settings')

    return render_template('addfunds.html', form=form)


@app.route('/confirmSHARELINK', methods=['POST', 'GET'])
@login_required
def confirmSHARELINK():
    link = request.form["link"]

    curr = db.session.query(models.User).filter_by(id=current_user.id).first()

    request_post = db.session.query(models.Post).filter_by(id=int(request.form['request_id'])).first()
    r = requests.get(link)
    text = r.text
    tree = html.fromstring(text)
    message = tree.xpath('//meta[@name="twitter:description"]/@content')[0]
    if request_post.link in message and request_post.content in message:
        request_post.posted = 1
        request_post.SHARELINK = link
        db.session.commit()

        t = db.session.query(models.Channel).filter_by(id=request_post.channel_id).first()
        curr.current_balance += t.price
        db.session.commit()
        flash("Great! In 48 hours we will check out the post existence and transfer money to your virtual wallet!")

    else:
        flash('Oops... Didn\'t find the post or it differs from the requested one.')

    return redirect('/user/%s' % current_user.id)


if __name__ == '__main__':
    # update.run()
    app.run(debug=True)
