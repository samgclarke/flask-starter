"""Authentication views blueprint."""
import datetime
from flask import Blueprint, flash, g, redirect, render_template, request, \
    url_for
from flask.ext.login import LoginManager, current_user, login_required,  \
    login_user, logout_user
from flask.ext.babel import lazy_gettext as _

# namespace .flaskstarter
from .. import app, db
from ..decorators import check_confirmed
from ..email import send_email
from ..logs import logger
from ..models import User
from ..token import confirm_token, generate_confirmation_token
from ..forms import LoginForm, RegistrationForm, ResetPasswordForm,\
    ConfirmResetPasswordForm


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


def send_confirm_email(user_email=None, username=None, confirm_url=None):
    """Send confirm email address."""
    if app.config['TESTING']:
        msg = 'Email not sent. You are in TESTING mode!'
        print(msg)
        logger.info(msg)
        return True
    root_url = app.config.get('ROOT_URL')
    with app.app_context():
        html = render_template(
            'user/activate.html',
            confirm_url=confirm_url,
            username=username,
            root_url=root_url
        )
        subject = _(u'Please confirm your email.')
        try:
            send_email(user_email, subject, html)
            logger.info(
                'confirmation email sent to {}'.format(user_email)
            )
            return True
        except Exception as e:
            print('Error {}'.format(e))
            logger.error(
                'confirmation email could not be sent. User {0}. Error {1}'
                .format(user_email, e)
            )
            return False


############
#  Routes  #
############
@auth.route('/en/register/', endpoint="register_en",
            methods=['GET', 'POST'])
@auth.route('/es/register/', endpoint="register_es",
            methods=['GET', 'POST'])
def register():
    """Register user."""
    form = RegistrationForm(request.form, country='CL')
    if request.method == 'POST' and form.validate():
        email_exists = User.query.filter_by(email=form.email.data).first()
        if email_exists:
            flash(
                _(u'Email address already exists.'), 'warning'
            )
        else:
            user = User(
                username=form.username.data,
                email=form.email.data,
            )
            user.hash_password(form.password.data)
        try:
            db.session.add(user)
            db.session.commit()
            #  generate token and send email
            token = generate_confirmation_token(user.email)
            confirm_url = url_for(
                'auth.confirm_' + g.language,
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
                _(u'Thanks for registering with us. \
                A confirmation email has been sent via email.'), 'success'
            )
        except Exception as e:
            # TODO deal with duplicate email addresses
            db.session.rollback()
            logger.error(
                'new user could not be registered. {0}. {1}'.format(g.user, e)
            )
        finally:
            db.session.close()
        return redirect(url_for('auth.login_' + g.language))
    return render_template(
        'register.html',
        form=form,
    )


@auth.route('/en/unconfirmed/', endpoint="unconfirmed_en")
@auth.route('/es/unconfirmed/', endpoint="unconfirmed_es")
def unconfirmed():
    """Return unconfirmed template."""
    if hasattr(current_user, 'confirmed') and current_user.confirmed:
        return redirect(url_for('auth.login_' + g.language))
    flash(_(u'Please confirm your account!'), 'warning')
    return render_template('unconfirmed.html')


@auth.route('/en/confirm/<token>/', endpoint="confirm_en")
@auth.route('/es/confirm/<token>/', endpoint="confirm_es")
def confirm_email(token):
    """Confirm token with email address using token."""
    user = None
    email = confirm_token(token)
    if email:
        try:
            user = User.query.filter_by(email=email).first()
        except Exception as e:
            flash(
                _(u'Sorry, we could not find your account in our database.'),
                'warning'
            )
            logger.error('error {}. email {}'.format(e, email))
        if not user:
            logger.error(
                'user could not be confirmed. email {}'.format(email)
            )
            flash(_(u'We could not verify your email address.'), 'warning')
            return redirect(url_for('auth.register_' + g.language))
        if user.confirmed:
            flash(_(u'Account already confirmed. Please login.'), 'success')
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
            flash(_(u'You have confirmed your account. Thanks!'), 'success')
    else:
        flash(
            _(u'The confirmation link is invalid or has expired.'),
            'warning'
        )
    return redirect(url_for('auth.login_' + g.language))


@auth.route('/en/reset_password/',
            endpoint="reset_password_en", methods=['GET', 'POST'])
@auth.route('/es/reset_password/',
            endpoint="reset_password_es", methods=['GET', 'POST'])
@check_confirmed
def reset_password():
    """Request password reset."""
    form = ResetPasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        #  check user email exists
        email = request.form['email'].strip()
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_confirmation_token(user.email)
            confirm_url = url_for(
                'auth.confirm_reset_password_' + g.language,
                token=token,
                _external=True
            )
            html = render_template(
                'user/password_reset_email.html',
                confirm_url=confirm_url,
                username=user.username
            )
            subject = -(u'Password Reset Request')
            send_email(email, subject, html)
            msg = u'Password reset request email sent to {}'.format(user.email)
            logger.info(_(msg))
            flash(msg, 'success')
            return redirect(url_for('auth.login_' + g.language))
        #  flash('Email address not found for any user', 'warning')
        flash(
            _(u'Email address not found for any user.'),
            'warning'
        )
    return render_template(
        'reset_password_request.html',
        form=form
    )


@auth.route('/en/confirm_reset_password/<token>/',
            endpoint="confirm_reset_password_en", methods=['GET', 'POST'])
@auth.route('/es/confirm_reset_password/<token>/',
            endpoint="confirm_reset_password_es", methods=['GET', 'POST'])
@check_confirmed
def confirm_reset_password(token):
    """Confirm password reset."""
    form = ConfirmResetPasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        try:
            email = confirm_token(token)
        except Exception as e:
            flash(
                _(u'The confirmation link is invalid or has expired.'),
                'warning'
            )
        user = User.query.filter_by(email=email).first_or_404()
        if not user.confirmed:
            flash(
                _(u'You must confirm your account first.'),
                'warning'
            )
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
                error_msg = u'Your password could not be changed at this time. \
                    {}'.format(user)
                logger.error('{0} {1}'.format(error_msg, e))
                flash(_(error_msg), 'warning')
                raise
            finally:
                db.session.close()
            flash(
                _(u'You have successfully changed your password.'),
                'success'
            )
            return redirect(url_for('auth.login_' + g.language))
    return render_template(
        'reset_password_confirm.html',
        token=token,
        form=form
    )


@auth.route('/en/login/', endpoint="login_en",
            methods=['GET', 'POST'])
@auth.route('/es/login/', endpoint="login_es",
            methods=['GET', 'POST'])
def login():
    """User login."""
    form = LoginForm(request.form)
    # is user authenticated go straight to default template
    if g.user.is_authenticated:
        return redirect(url_for('index_' + g.language), code=302)
    if request.method == 'POST' and form.validate():
        email = request.form['email']
        password = request.form['password']
        registered_user = User.query.filter_by(
            email=email
        ).first()
        if registered_user is None or not registered_user.verify_password(password):
            msg = u'Email or Password is invalid'
            logger.info(
                '{0} email: {1}'.format(msg, email)
            )
            flash(_(msg), 'warning')
            return redirect(url_for('auth.login_' + g.language))
        if not registered_user.confirmed:
            logger.info(
                'unconfirmed user login attempt. email: {0}'.format(email)
            )
            return redirect(url_for('auth.unconfirmed_' + g.language))
        login_user(registered_user)
        logger.info(
            'user login.  user: {0}'.format(current_user)
        )
        return redirect(url_for('index_' + g.language), code=302)
    return render_template(
        'login.html',
        form=form
    )


@auth.route('/logout')
@login_required
def logout():
    """User logout."""
    logger.info(
        'user logout. user: {0}'.format(current_user)
    )
    logout_user()
    return redirect(url_for('auth.login_' + g.language))
