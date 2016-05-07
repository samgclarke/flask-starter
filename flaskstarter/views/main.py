"""Main application views."""
from flask import Blueprint, g, render_template, request
from flask.ext.login import current_user
from flask.ext.babel import lazy_gettext
from flaskstarter import app, babel


main = Blueprint('main', __name__)


#########
# BABEL #
#########
@babel.localeselector
def get_locale():
    """Get user language."""
    lang = request.path[1:].split('/', 1)[0]
    if lang in app.config.get('LANGUAGES').keys():
        return lang
    elif request.accept_languages:
        return request.accept_languages.best_match(['es', 'en'])
    else:
        return 'en'


@app.before_request
def before_request():
    """Store data in session before each request."""
    g.user = current_user
    g.babel = babel
    g.language = get_locale()


@app.route('/en/', endpoint="index_en", methods=['GET'])
@app.route('/es/', endpoint="index_es", methods=['GET'])
def index():
    """Index."""
    return render_template('index.html')
