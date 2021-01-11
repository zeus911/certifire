import json
from datetime import datetime
from urllib.parse import urljoin

import josepy as jose
from certifire import config, db, users
from certifire.plugins.acme import crypto
from sqlalchemy import Column, ForeignKey, Integer, String, Text
from sqlalchemy.orm import relationship


class Account(db.Model):
    __tablename__ = 'acme_account'
    id = Column(Integer, primary_key=True)
    email = Column(String(128))
    key = Column(Text())
    uri = Column(String(128))
    server = Column(String(128))
    directory_uri = Column(String(128))
    user_id = Column(Integer, ForeignKey("users.id"))
    contents = Column(Text())

    organization = Column(Text())
    organizational_unit = Column(Text())
    country = Column(Text())
    state = Column(Text())
    location = Column(Text())

    order_account = relationship("Order", foreign_keys="Order.account_id")

    def __init__(self, user_id, email, server=None, key=None, uri=None, 
                    organization: str = config.CERTIFIRE_ORGANIZATION,
                    organizational_unit: str = config.CERTIFIRE_ORGANIZATIONAL_UNIT,
                    country: str = config.CERTIFIRE_COUNTRY,
                    state: str = config.CERTIFIRE_STATE,
                    location: str = config.CERTIFIRE_LOCATION):
        self.email = email
        self.server = server if server else config.LETS_ENCRYPT_PRODUCTION
        self.directory_uri = urljoin(self.server, 'directory')
        self.key = key
        self.uri = uri
        self.user_id = user_id
        self.organization = organization
        self.organizational_unit = organizational_unit
        self.country = country
        self.state = state
        self.location = location

    @property
    def thumbprint(self):
        return crypto.generate_jwk_thumbprint(crypto.load_private_key(
            self.key.encode("utf8")))
    
    @property
    def json(self):
        return json.dumps({
            'id': self.id,
            'email': self.email,
            'key': self.key,
            'uri': self.uri,
            'server': self.server,
            'directory_uri': self.directory_uri,
            'organization': self.organization,
            'organizational_unit': self.organizational_unit,
            'country': self.country,
            'state': self.state,
            'location': self.location,
            'user_id': self.user_id
        }).encode("utf-8")

class Order(db.Model):
    __tablename__ = 'orders'
    id = Column(Integer, primary_key=True)
    hash = Column(String(64), nullable=False)
    uri = Column(Text())
    type = Column(Text())
    provider = Column(Text())
    domains = Column(Text())
    destination_id = Column(Integer, ForeignKey("destinations.id"))
    account_id = Column(Integer, ForeignKey("acme_account.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String(16), nullable=False)
    resolved_cert_id = Column(Integer)
    contents = Column(Text())

    email = Column(Text())
    organization = Column(Text())
    organizational_unit = Column(Text())
    country = Column(Text())
    state = Column(Text())
    location = Column(Text())

    csr = Column(Text())
    key = Column(Text())

    certificate_order = relationship("Certificate", foreign_keys="Certificate.order_id")

    def __init__(self, destination_id:int, domains: list, type, provider, account_id, user_id=1, hash=None, csr=None, key=None, 
                email=None, organization=None, organizational_unit=None, country=None, state=None, location=None):
        self.destination_id = destination_id
        self.domains = ','.join(domains)
        self.type = type
        self.provider = provider
        self.account_id = account_id
        self.user_id = user_id
        self.hash = hash
        self.status = 'Pending'
        self.csr = csr
        self.key = key

        self.email = email
        self.organization = organization
        self.organizational_unit = organizational_unit
        self.country = country
        self.state = state
        self.location = location

    @property
    def expired(self):
        if self.contents['status'] == "expired":
            return True
        order_timestamp = datetime.strptime(self.contents['expires'][0:19],
                                            "%Y-%m-%dT%H:%M:%S")
        return order_timestamp < datetime.now()

    @property
    def invalid(self):
        return self.contents['status'] == "invalid"

    @property
    def json(self):
        return json.dumps({
            'id': self.id,
            'hash': self.hash,
            'contents': json.loads(self.contents)['body'],
            'uri': self.uri,
            'type': self.type,
            'provider': self.provider,
            'key': self.key,
            'csr': self.csr,
            'domains': self.domains.split(','),
            'account_id': self.account_id,
            'user_id': self.user_id,
            'status': self.status,
            'resolved_cert_id': self.resolved_cert_id,
            'organization': self.organization,
            'organizational_unit': self.organizational_unit,
            'country': self.country,
            'state': self.state,
            'location': self.location
        }).encode("utf-8")

class Certificate(db.Model):
    __tablename__ = "certificates"
    id = Column(Integer, primary_key=True)
    external_id = Column(String(128))
    body = Column(Text())
    intermediate = Column(Text())
    chain = Column(Text())
    csr = Column(Text())
    private_key = Column(Text())
    expiry = Column(String(12))
    fingerprint = Column(Text())
    status = Column(String(16), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    order_id = Column(Integer, ForeignKey("orders.id"))

    #certificate_order = relationship("Order", foreign_keys="Order.resolved_cert_id")

    @property
    def json(self):
        return json.dumps({
            'id': self.id,
            'fingerprint': self.fingerprint,
            'expiry': self.expiry,
            'body': self.body,
            'intermediate': self.intermediate,
            'chain': self.chain,
            'key': self.private_key,
            'csr': self.csr,
            'order_id': self.order_id,
            'user_id': self.user_id,
            'status': self.status
        }).encode("utf-8")
