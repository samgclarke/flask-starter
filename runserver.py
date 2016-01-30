import os
import logging
from flask_starter import app
print(os.environ['APP_SETTINGS'])
print(os.environ['DATABASE_URL'])

if app.debug:
    #  supress INFO level logs when debug
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)

app.run(debug=True, threaded=True, port=5000)
