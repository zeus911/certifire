import os

#SQLALCHEMY_DATABASE_URI = 'postgresql://certifire:certifire@postgres:5432/certifire'
SQLALCHEMY_DATABASE_URI = os.getenv('DB', 'postgresql://certifire:certifire@postgres:5432/certifire')
CERTIFIRE_TOKEN_SECRET = 'loremipsum'
CERTIFIRE_PATH = '~/.certifire'

#LETS_ENCRYPT_PRODUCTION = "https://acme-v02.api.letsencrypt.org/"
LETS_ENCRYPT_PRODUCTION = "https://acme-staging-v02.api.letsencrypt.org/"
DEFAULT_CERT_KEY_SIZE = 4096
DEFAULT_AUTH_TYPE = 'dns'
DEFAULT_DNS = 'route53'
EXPIRATION_FORMAT = "%Y-%m-%d"

CERTIFIRE_EMAIL = 'githinmanesh@gmail.com'
CERTIFIRE_ORGANIZATION = 'certifire'
CERTIFIRE_ORGANIZATIONAL_UNIT = 'testing'
CERTIFIRE_COUNTRY = 'IN'
CERTIFIRE_STATE = 'KL'
CERTIFIRE_LOCATION = 'QLN'

IDENTRUST_CROSS_SIGNED_LE_ICA = False
IDENTRUST_CROSS_SIGNED_LE_ICA_EXPIRATION_DATE = "17/03/21"
IDENTRUST_CROSS_SIGNED_LE_ICA = None

VALID_DNS_PROVIDERS = ['route53']