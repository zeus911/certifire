FROM python:3.9.1-slim-buster

WORKDIR /usr/src/app
COPY . /usr/src/app

RUN pip install --upgrade pip
RUN pip install -r requirements.txt
RUN python setup.py install

ENV DB 'postgresql://certifire:certifire@postgres:5432/certifire'
