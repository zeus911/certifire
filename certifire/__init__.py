from flask import Flask, jsonify
from flask_httpauth import HTTPBasicAuth
from flask_migrate import Migrate, MigrateCommand
from flask_sqlalchemy import SQLAlchemy

import certifire.config as config
from certifire.config import app_config

__author__ = "Githin Manesh <githinmanesh@gmail.com>"
__version__ = (0, 3, 0)
__licence__ = "MIT"


def get_version():
    return ".".join(map(str, __version__))


def get_author():
    return __author__.split(" <")[0]


def get_author_email():
    return __author__.split(" <")[1][:-1]

def create_app(config_name):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(app_config[config_name])
    app.config.from_object(app_config[config_name])
    #app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)

    @app.route('/')
    def init():
        return jsonify({'data': 'Hello World'})

    from certifire import users
    app.register_blueprint(users.bp)

    return app

db = SQLAlchemy()
auth = HTTPBasicAuth()
app = create_app('development')
