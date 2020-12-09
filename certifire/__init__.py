from flask import Flask
from flask_httpauth import HTTPBasicAuth
from flask_sqlalchemy import SQLAlchemy

import certifire.config as config

app = Flask(__name__)
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

app.config['SECRET_KEY'] = config.CERTIFIRE_TOKEN_SECRET
#app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_DATABASE_URI'] = config.SQLALCHEMY_DATABASE_URI
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
