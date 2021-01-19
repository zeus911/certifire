import os
import unittest

from flask_migrate import Migrate, MigrateCommand
from flask_script import Manager

from certifire import app, database, db, users
from certifire.plugins.acme import views
from certifire.plugins.destinations import views

manager = Manager(app)
migrate = Migrate(app, db)

@manager.command
def create_db():
    """Creates the db tables."""
    db.create_all()


@manager.command
@manager.option('-p', '--passwd', dest='pwd', default='changeme')
def init(pwd='changeme'):
    """Creates the db tables and admin user"""
    db.create_all()
    if users.User.query.filter_by(username='admin').first() is not None:
        print("Admin user already exists")
    else:
        if not pwd:
            pwd = input("Enter password for admin user: ")
        user = users.User('admin', pwd, True)
        database.add(user)


@manager.command
def drop_db():
    """Drops the db tables."""
    # TODO Cascade delete all users, acme accounts and revoke all certificates
    db.drop_all()


def main():
    manager.run()

manager.add_command('db', MigrateCommand)

@manager.command
def test():
    """Runs the unit tests without test coverage."""
    tests = unittest.TestLoader().discover('./tests', pattern='test*.py')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if result.wasSuccessful():
        return 0
    return 1

if __name__ == '__main__':
    main()
