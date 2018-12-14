FROM ubuntu:latest
MAINTAINER Sam Clarke "samclarke.g@gmail.com"
RUN apt-get update -y
RUN apt-get install -y python-pip python-dev build-essential
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
#ENTRYPOINT ["python"]
#CMD ["runserver.py"]

#CMD ["gunicorn --bind 0.0.0.0:5000 wsgi:app "]
COPY start.sh /start.sh
CMD ["/start.sh"]


#  Environmental Variables
ENV APP_SETTINGS "config.DevelopmentConfig"
ENV DATABASE_URL="sqlite:///home/sam/flask-projects/tests.db"
ENV APP_MAIL_USERNAME="cronneloctopus"
ENV APP_MAIL_PASSWORD="joachim45"
ENV MAIL_DEFAULT_SENDER="cronneloctopus@gmail.com"
ENV LOGGING_URL="logs3.papertrailapp.com:13806"
ENV CONTACT_EMAIL="cronneloctopus@gmail.com"
