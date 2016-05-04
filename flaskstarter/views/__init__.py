# namespace .flaskstarter
from flaskstarter import app, db
from flaskstarter.views.auth import auth
from flaskstarter.views.main import main

app.register_blueprint(auth)
app.register_blueprint(main)
