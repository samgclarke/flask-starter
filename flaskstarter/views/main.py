from flask import Blueprint, render_template
from flaskstarter import app, db


main = Blueprint('main', __name__)


@app.route('/', methods=['GET', 'POST'])
def index():
    """Index."""
    return render_template('index.html')
