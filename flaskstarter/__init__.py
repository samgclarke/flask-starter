import os
from flask import Flask
from flask.ext.sqlalchemy import SQLAlchemy
from flask_mail import Mail


############
# APP INIT #
############
app = Flask(__name__)
#  load settings from Config class,
#  depending on environmental variable
app.config.from_object(os.environ['APP_SETTINGS'])
db = SQLAlchemy(app)
mail = Mail(app)


# import into flaskstarter namespace
import flaskstarter.views
import flaskstarter.models
import flaskstarter.logs
