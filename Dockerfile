FROM python:3.8.1-slim-buster

WORKDIR /usr/src/app

# set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN pip install --upgrade pip

# copy project
COPY . /usr/src/app/

RUN pip install -r requirements.txt
