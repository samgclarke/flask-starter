"""Run Develoipment Server."""

import os
import logging
from flaskstarter import app


print('APP CONFIG --> {}'.format(os.environ['APP_SETTINGS']))
print('APP DB_URL --> {}'.format(app.config['SQLALCHEMY_DATABASE_URI']))

if app.debug:
    #  supress INFO level logs when debug
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

app.run(
    debug=True,
    host='0.0.0.0',
    port=5000,
    threaded=True,
    use_reloader=False
)
