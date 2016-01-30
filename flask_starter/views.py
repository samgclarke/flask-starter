from flask import render_template, request, flash, url_for, redirect, g, \
    Response
from flask.ext.login import LoginManager, login_user, logout_user, \
    current_user, login_required
import json

# namespace .flask_starter
from flask_starter import app, db
from flask_starter.models import User
from flask_starter.token import generate_confirmation_token, confirm_token
from flask_starter.email import send_email
from flask_starter.decorators import check_confirmed
# logging
from flask_starter.logs import logger, syslog, loglevel
from logging.handlers import SysLogHandler


###############
# LOGIN UTILS #
###############
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


@app.before_request
def before_request():
    g.user = current_user


#  FILE UPLOADS
ALLOWED_EXTENSIONS = set(['pdf', 'fountain'])


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS


##############
#  Register  #
##############
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    #  check if email exists
    email = request.form['email'].strip()
    email_exists = User.query.filter_by(email=email).all()
    if email_exists:
        flash('Email address already exists', 'warning')
        return render_template('register.html')
    pwd = request.form['password'].strip()
    user = User(
        username=request.form['username'].strip(),
        email=email,
        confirmed=False
    )
    user.hash_password(pwd)
    try:
        db.session.add(user)
        db.session.commit()
        logger.info(
            'new user registered. {}'.format(user)
        )
    except Exception as e:
        # TODO deal with duplicate email addresses
        db.session.rollback()
        logger.error('new user could not be registered. {0}. {1}'.format(user, e))
        raise
    finally:
        db.session.close()

    token = generate_confirmation_token(user.email)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('user/activate.html', confirm_url=confirm_url)
    subject = "Please confirm your email"
    send_email(user.email, subject, html)
    logger.info(
        'confirmation email sent to {}'.format(user.email)
    )
    flash('A confirmation email has been sent via email.', 'success')
    return redirect(url_for('login'))


@app.route('/unconfirmed')
def unconfirmed():
    if hasattr(current_user, 'confirmed') and current_user.confirmed:
        return redirect(url_for('login'))
    flash('Please confirm your account!', 'warning')
    return render_template('unconfirmed.html')


@app.route('/confirm/<token>')
def confirm_email(token):
    try:
        email = confirm_token(token)
    except Exception as e:
        flash('The confirmation link is invalid or has expired.', 'warning')
    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please login.', 'success')
    else:
        user.confirmed = True
        user.confirmed_on = datetime.datetime.now()
        try:
            db.session.add(user)
            db.session.commit()
            logger.info(
                'user confirmed. {}'.format(user)
            )
        except Exception as e:
            db.session.rollback()
            logger.error(
                'user could not be confirmed. {0}. {1}'.format(user, e)
            )
            raise
        finally:
            db.session.close()
        flash('You have confirmed your account. Thanks!', 'success')
    return redirect(url_for('login'))


@app.route('/reset_password', methods=['GET', 'POST'])
@login_required
@check_confirmed
def reset_password():
    if request.method == 'GET':
        return render_template('reset_password_request.html')
    #  check user email exists
    email = request.form['email'].strip()
    user = User.query.filter_by(email=email).first()
    if user:
        token = generate_confirmation_token(user.email)
        confirm_url = url_for(
            'confirm_reset_password', token=token, _external=True
        )
        html = render_template(
            'user/password_reset_email.html', confirm_url=confirm_url
        )
        subject = "Password Reset Request"
        send_email(email, subject, html)
        msg = 'Password reset request email sent to {}'.format(user.email)
        logger.info(msg)
        flash(msg, 'success')
        return redirect(url_for('login'))
    #  flash('Email address not found for any user', 'warning')
    flash('Email address not found for any user', 'warning')
    return render_template('reset_password_request.html')


@app.route('/confirm_reset_password/<token>', methods=['GET', 'POST'])
@login_required
@check_confirmed
def confirm_reset_password(token):
    if request.method == 'GET':
        return render_template(
            'reset_password_confirm.html',
            token=token,
        )
    try:
        email = confirm_token(token)
    except Exception as e:
        flash('The confirmation link is invalid or has expired.', 'warning')
    user = User.query.filter_by(email=email).first_or_404()
    if not user.confirmed:
        flash('You must confirm your account first', 'warning')
    else:
        pwd = request.form['password'].strip(),
        user.password_hash = user.hash_password(pwd)
        try:
            db.session.add(user)
            db.session.commit()
            logger.info(
                'Password reset. {}'.format(user)
            )
        except Exception as e:
            db.session.rollback()
            error_msg = 'Your password could not be changed at this time. \
                {}'.format(user)
            logger.error('{0} {1}'.format(error_msg, e))
            flash(error_msg, 'warning')
            raise
        finally:
            db.session.close()
        flash('You have successfully changed your password.', 'success')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    # is user authenticated go straight to default template
    if g.user.is_authenticated():
        return redirect(url_for('index'))
    # if user user not authenticated -> login form
    if request.method == 'GET':
        return render_template('login.html')
    email = request.form['email']
    password = request.form['password']
    remember_me = False
    if 'remember_me' in request.form:
        remember_me = True
    registered_user = User.query.filter_by(
        email=email
    ).first()
    if registered_user is None or not registered_user.verify_password(password):
        msg = 'Email or Password is invalid'
        logger.info(
            '{0} email: {1}'.format(msg, email)
        )
        flash(msg, 'warning')
        return redirect(url_for('login'))
    if not registered_user.confirmed:
        logger.info(
            'unconfirmed user login attempt. email: {0}'.format(email)
        )
        return redirect(url_for('unconfirmed'))
    login_user(registered_user, remember=remember_me)
    logger.info('user login.  user: {0}'.format(current_user))
    return redirect(url_for('index'))


@app.route('/logout')
@login_required
def logout():
    logger.info(
        'user logout. user: {0}'.format(current_user)
    )
    logout_user()
    return redirect(url_for('login'))


###############
# APPLICATION #
###############
@app.route('/')
def index():
    '''
    Landing Page
    '''
    return render_template(
        'index.html',
    )


@app.route('/validate/')
def validate_coupon():
    #  code can be 
    coupon_valid = None
    form = CouponForm()
    if request.POST:
       if form.validate_on_submit():
            #  validate coupon
            #  coupon_valid = Coupon.validate_code(form.coupon)
            #  TODO: Honduran codes are worth 5? -> unlock a team
            pass
    return render_template(
        'validate.html',
        code_valid=coupon_valid,
    )

@app.route('/myteams/')
@login_required
@check_confirmed
def myteams():
    #  can we get this info in the template?
    successful_coupons = g.user.unlocks
    return render_template(
        'myteams.html',
        successful_coupons=successful_coupons,
    )


@app.errorhandler(404)
def page_not_found(e):
    logger.error('404 Page Not Found. {}'.format(request))
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(e):
    logger.error('500 Server Error. {}'.format(request))
    return render_template('500.html'), 500
