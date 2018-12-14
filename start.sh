#!/bin/bash

# Start Gunicorn processes
echo Starting Gunicorn.
exec gunicorn --bind 0.0.0.0:5000 wsgi:app --workers 3

# exec gunicorn flaskstarter.wsgi:app \
#    --bind 0.0.0.0:5000 \
#    --workers 3

