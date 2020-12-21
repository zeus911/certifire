import os

SQLALCHEMY_DATABASE_URI = 'postgresql://certifire:certifire@127.0.0.1:5432/certifire'
CERTIFIRE_TOKEN_SECRET = 'loremipsum'
CERTIFIRE_PATH = '~/.certifire'

#LETS_ENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/"
LETS_ENCRYPT_PRODUCTION = "https://acme-staging-v02.api.letsencrypt.org/"
DEFAULT_ACCOUNT_PATH = 'account.json'
DEFAULT_CERT_KEY_SIZE = 4096

current_path = os.path.dirname(os.getcwd())
paths = {
        'authorizations': os.path.join(current_path, "authorizations"),
        'current': current_path,
        'orders': os.path.join(current_path, "orders"),
    }
