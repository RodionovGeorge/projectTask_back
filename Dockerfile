#FROM ubuntu:18.04
FROM python:3.6

RUN apt-get update && apt-get install -y texlive-latex-base
RUN apt-get install -y poppler-utils
RUN pip install pillow
RUN pip install pdf2image
RUN pip install Flask uWSGI
RUN pip install Flask-SQLAlchemy
RUN pip install Flask-Migrate
RUN pip install Werkzeug
RUN pip install flask-restful
RUN pip install psycopg2-binary
RUN pip install Flask-Mail
RUN pip install flask-bcrypt

WORKDIR /app

ENTRYPOINT ["./entrypoint.sh"]
