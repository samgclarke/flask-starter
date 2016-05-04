"""Authentication views blueprint."""
import datetime
from flask import Blueprint, flash, g, redirect, render_template, request, \
    url_for
from flask.ext.login import LoginManager, current_user, login_required,  \
    login_user, logout_user

# namespace .uefa
from flaskstarter import app, db
from flaskstarter.decorators import check_confirmed
from flaskstarter.email import send_email
from flaskstarter.logs import logger
from flaskstarter.models import User
from flaskstarter.token import confirm_token, generate_confirmation_token


auth = Blueprint('auth', __name__)


###############
# LOGIN UTILS #
###############
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth.login'


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


##############
#  Register  #
##############
def send_confirm_email(user_email=None, username=None, confirm_url=None):
    """Send confirm email address."""
    print('send email!!!!!!!!!!!!!')
    if app.debug:
        logger.info('email not sent. You are in DEBUG mode!')
        return True
    root_url = app.config.get('ROOT_URL')
    with app.app_context():
        html = render_template(
            'user/activate.html',
            confirm_url=confirm_url,
            username=username,
            root_url=root_url
        )
        subject = 'Please confirm your email'
        try:
            send_email(user_email, subject, html)
            logger.info(
                'confirmation email sent to {}'.format(user_email)
            )
            return True
        except Exception as e:
            logger.error(
                'confirmation email could not be sent. User {0}. Error {1}'
                .format(user_email, e)
            )
            return False


@auth.route('/register', methods=['GET', 'POST'])
def register():
    """Register user."""
    # because of the unbounce landing page
    if g.user.is_authenticated():
        return redirect(url_for('auth.login', code=302))
    # GET request (no data)
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
        #  generate token and send email
        token = generate_confirmation_token(user.email)
        confirm_url = url_for(
            'auth.confirm_email',
            token=token,
            _external=True
        )
        send_confirm_email(
            user_email=user.email,
            confirm_url=confirm_url,
            username=user.username
        )
        logger.info(
            'new user registered. {}'.format(user)
        )
        flash(
            'Thanks for registering with us. \
            A confirmation email has been sent via email.', 'success'
        )
    except Exception as e:
        # TODO deal with duplicate email addresses
        db.session.rollback()
        logger.error(
            'new user could not be registered. {0}. {1}'.format(user, e)
        )
    finally:
        db.session.close()
    return redirect(url_for('auth.login'))


@auth.route('/unconfirmed')
def unconfirmed():
    """Return unconfirmed template."""
    if hasattr(current_user, 'confirmed') and current_user.confirmed:
        return redirect(url_for('auth.login'))
    flash('Please confirm your account!', 'warning')
    return render_template('unconfirmed.html')


@auth.route('/confirm/<token>')
def confirm_email(token):
    """Confirm token with email address using token."""
    user = None
    email = confirm_token(token)
    if email:
        try:
            user = User.query.filter_by(email=email).first()
        except Exception as e:
            flash(
                'Sorry, we could not find your account in our database.', 'warning'
            )
            logger.error('error {}. email {}'.format(e, email))
        if not user:
            logger.error(
                'user could not be confirmed. email {}'.format(email)
            )
            flash('We could not verify your email address.', 'warning')
            return redirect(url_for('auth.register'))
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
    else:
        flash('The confirmation link is invalid or has expired.', 'warning')
    return redirect(url_for('auth.login'))


@auth.route('/reset_password', methods=['GET', 'POST'])
@check_confirmed
def reset_password():
    """Request password reset."""
    if request.method == 'GET':
        return render_template('reset_password_request.html')
    #  check user email exists
    email = request.form['email'].strip()
    user = User.query.filter_by(email=email).first()
    if user:
        token = generate_confirmation_token(user.email)
        confirm_url = url_for(
            'auth.confirm_reset_password', token=token, _external=True
        )
        html = render_template(
            'user/password_reset_email.html', confirm_url=confirm_url
        )
        subject = "Password Reset Request"
        send_email(email, subject, html)
        msg = 'Password reset request email sent to {}'.format(user.email)
        logger.info(msg)
        flash(msg, 'success')
        return redirect(url_for('auth.login'))
    #  flash('Email address not found for any user', 'warning')
    flash('Email address not found for any user', 'warning')
    return render_template('reset_password_request.html')


@auth.route('/confirm_reset_password/<token>', methods=['GET', 'POST'])
@check_confirmed
def confirm_reset_password(token):
    """Confirm password reset."""
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
        pwd = request.form['password'].strip()
        user.hash_password(pwd)
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
    return redirect(url_for('auth.login'))


@auth.route('/login', methods=['GET', 'POST'])
def login():
    """User login."""
    # is user authenticated go straight to default template
    if g.user.is_authenticated():
        return redirect(url_for('index'), code=302)
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
        return redirect(url_for('auth.login'))
    if not registered_user.confirmed:
        logger.info(
            'unconfirmed user login attempt. email: {0}'.format(email)
        )
        return redirect(url_for('auth.unconfirmed'))
    login_user(registered_user, remember=remember_me)
    logger.info('user login.  user: {0}'.format(current_user))

    return redirect(url_for('index'), code=302)


@auth.route('/logout')
@login_required
def logout():
    """User logout."""
    logger.info(
        'user logout. user: {0}'.format(current_user)
    )
    logout_user()
    return redirect(url_for('auth.login'))
