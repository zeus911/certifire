import os
import time

import jwt
from flask import abort, Blueprint, g, jsonify, request, url_for
from sqlalchemy import Boolean, Column, Integer, String
from sqlalchemy.orm import relationship
from werkzeug.security import check_password_hash, generate_password_hash

from certifire import auth, db
import certifire.config as config

bp = Blueprint("users", __name__)

class User(db.Model):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String(32), index=True)
    password_hash = Column(String(128))
    is_admin = Column(Boolean())

    user_acme_account = relationship("Account", foreign_keys="Account.user_id")
    order_account = relationship("Order", foreign_keys="Order.user_id")
    certificate_account = relationship("Certificate", foreign_keys="Certificate.user_id")
    user_destination = relationship("Destination", foreign_keys="Destination.user_id")

    def __init__(self, username, password, is_admin=False):
        self.username = username
        self.hash_password(password)
        self.is_admin = is_admin

    def hash_password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_auth_token(self, expires_in=600):
        return jwt.encode(
            {'id': self.id, 'exp': time.time() + expires_in},
            config.CERTIFIRE_TOKEN_SECRET, algorithm='HS256')

    @staticmethod
    def verify_auth_token(token):
        try:
            data = jwt.decode(token, config.CERTIFIRE_TOKEN_SECRET,
                              algorithms=['HS256'])
        except:
            return
        return User.query.get(data['id'])


@auth.verify_password
def verify_password(username_or_token, password):
    # first try to authenticate by token
    user = User.verify_auth_token(username_or_token)
    if not user:
        # try to authenticate with username/password
        user = User.query.filter_by(username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@bp.route('/api/users', methods=['POST'])
@auth.login_required
def new_user():
    if not g.user.is_admin:
        abort(400)
    post_data = request.form
    username = post_data.get('username')
    password = post_data.get('password')
    if username is None or password is None:
        post_data = request.get_json(force=True)
        username = post_data.get('username')
        password = post_data.get('password')
        if username is None or password is None:
            abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        return (jsonify({'status': 'Username {} already exists'.format(username)}), 400)    # existing user
    user = User(username,password)
    db.session.add(user)
    db.session.commit()
    return (jsonify({'username': user.username}), 201,
            {'Location': url_for('users.get_user', id=user.id, _external=True)})


@bp.route('/api/users/<int:id>')
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify({'username': user.username})


@bp.route('/api/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return (jsonify({'token': token.decode('ascii'), 'duration': 600}), 200,
            {'token': token})


@bp.route('/api/resource')
@auth.login_required
def get_resource():
    return jsonify({'data': 'Hello, %s!' % g.user.username})

@bp.route('/api/public')
def init():
    return jsonify({'data': 'Hello World'})