from flask_script import Manager
import os

from certifire import app, db, users, certificates
from certifire.plugins.acme import models
from certifire.plugins.acme.register import register
from certifire.plugins.acme import views

manager = Manager(app)

@manager.command
def create_db():
    """Creates the db tables."""
    db.create_all()

@manager.command
def init():
    """Creates the db tables and admin user"""
    db.create_all()
    if users.User.query.filter_by(username='admin').first() is not None:
        print("Admin user already exists")
    else:
        pwd = input("Enter password for admin user: ")
        user = users.User('admin',pwd,True)
        db.session.add(user)
        db.session.commit()


@manager.command
def drop_db():
    """Drops the db tables."""
    db.drop_all()

def main():
    manager.run()

if __name__ == '__main__':
    main()