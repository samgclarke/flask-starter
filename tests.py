"""Unit Tests."""

import unittest
from flaskstarter import app, db
from flaskstarter.models import User
from flask import url_for
from flask.ext.testing import TestCase

# Note: can run individual tests:
# nosetests -s flaskstarter.tests.tests:FountainTestCase

TEST_USER = {
    'fullname': 'Joe Bar',
    'username': 'joebaz',
    'email': 'foo@bar.com',
    'password': 'foobar',
    'confirm': 'foobar',
}


class BaseTestCase(TestCase):
    """Abstract Base TestCase."""

    def create_app(self):
        """Return valid app object."""
        app.config.from_object('config.TestingConfig')
        return app

    def setUp(self):
        """Setup."""
        db.create_all()

    def tearDown(self):
        """Teardown."""
        db.session.remove()
        db.drop_all()

    def make_user(self, pwd=False, confirm=False):
        """Make a user object to test with."""
        user = User(
            username=TEST_USER['username'],
            email=TEST_USER['email'],
        )
        if pwd:
            user.password = user.hash_password(TEST_USER['password'])
        if confirm:
            user.confirmed = True
        db.session.add(user)
        db.session.commit()
        return user

    def login(self, c=None):
        """Login user."""
        login_url = 'auth.login'
        data = {
            'email': TEST_USER['email'],
            'password': TEST_USER['password']
        }
        resp = c.post(
            url_for(login_url),
            data=data
        )
        return resp


class DatabaseTests(BaseTestCase):
    """Teset db exists."""

    def test_user_creation(self):
        """Test user model can be created."""
        user = self.make_user(pwd=False, confirm=False)
        assert user in db.session


class AuthTestCase(BaseTestCase):
    """Test Authentication."""

    def test_register(self):
        """Test user can register."""
        with self.client as client:
            resp = client.post(
                url_for('auth.register'),
                data=TEST_USER
            )
        assert '<p>You should be redirected automatically to target URL: '\
               '<a href="/login">/login</a>.  If not click the link.' in resp.get_data()

    def test_register_email_exists_error(self):
        """Test user cannot register with same email."""
        login_url = 'auth.login'
        self.make_user(pwd=True, confirm=True)
        with self.client as client:
            resp = client.post(
                url_for('auth.register'),
                data={
                    'fullname': 'New User',
                    'username': 'newuser',
                    'email': TEST_USER['email'],
                    'password': 'newpass',
                    'confirm': 'newpass',
                }
            )
        self.assert_redirects(resp, url_for(login_url))

    def test_invalid_login(self):
        """Test that incorrect login returns to login page."""
        login_url = 'auth.login'
        with self.client as client:
            resp = client.post(
                url_for(login_url),
                data={
                    'email': TEST_USER['email'],
                    'password': 'wrongpass'
                }
            )
        self.assert_redirects(resp, url_for(login_url))

    def test_unconfirmed_login(self):
        """Test unconfirmed login."""
        self.make_user(pwd=True, confirm=False)
        with self.client as client:
            resp = self.login(c=client)
        self.assert_redirects(
            resp, url_for('auth.unconfirmed')
        )

    def test_confirmed_login(self):
        """Test condifmed login."""
        self.make_user(pwd=True, confirm=True)
        with self.client as client:
            resp = self.login(c=client)
        self.assert_redirects(
            resp, url_for('index')
        )

if __name__ == '__main__':
    unittest.main()
