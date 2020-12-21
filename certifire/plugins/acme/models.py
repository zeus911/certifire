import json

from certifire.plugins.acme.crypto import (generate_jwk_thumbprint, load_private_key,
                     export_private_key)
from sqlalchemy import Column, Integer, String, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from certifire import db, users, config

class Account(db.Model):
    __tablename__ = 'acme_account'
    id = Column(Integer, primary_key=True)
    email = Column(String(128))
    act_key = Column(Text(), nullable=False)
    act_uri = Column(String(128))
    server = Column(String(128))
    user_id = Column(Integer, ForeignKey("users.id"))

    order_account = relationship("Order", foreign_keys="Order.account_id")

    def __init__(self, key, uri=None, email=None, user_id=1, server=None):
        self.key = key
        self.uri = uri
        self.email = email
        self.user_id = user_id #User id set to 1 when using cli (Admin account)
        self.server = server if server else config.LETS_ENCRYPT_PRODUCTION

    @property
    def thumbprint(self):
        return generate_jwk_thumbprint(self.key)
    
    def finalize(self):
        self.act_key = export_private_key(self.key).decode("utf-8")
        self.act_uri = self.uri
    
    def initialize(self):
        self.key = load_private_key(self.act_key.encode("utf8"))
        self.uri = self.act_uri


class Authorization:

    def __init__(self, contents, uri, ty_pe):
        self.contents = contents
        self.uri = uri
        self.type = ty_pe
        self.certificate_uri = None
        self.certificate = {}


class Challenge:

    def __init__(self, contents, domain, expires, status, ty_pe, key):
        self.contents = contents
        self.domain = domain
        self.expires = expires
        self.status = status
        self.type = ty_pe
        self.key = key

    def serialize(self):
        return json.dumps({
            'contents': self.contents,
            'domain': self.domain,
            'expires': self.expires,
            'status': self.status,
            'type': self.type,
            'key': self.key
        }).encode('utf-8')

    @property
    def file_name(self):
        return "{}_challenge.json".format(self.domain)


class Order(db.Model):
    __tablename__ = 'orders'
    id = Column(Integer, primary_key=True)
    hash = Column(String(64), nullable=False)
    account_id = Column(Integer, ForeignKey("acme_account.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String(16), nullable=False)
    domains = Column(Text())
    resolved_cert_id = Column(Integer)

    certificate_order = relationship("Certificate", foreign_keys="Certificate.order_id")

    def __init__(self, contents, uri, ty_pe, account_id, user_id=1, hash=None):
        self.contents = contents
        self.uri = uri
        self.type = ty_pe
        self.certificate_uri = None
        self.certificate = {}
        self.key = None
        self.account_id = account_id
        self.user_id = user_id
        self.hash = hash
        self.status = 'Pending'

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

    def serialize(self):
        return json.dumps({
            'id': self.id,
            'hash': self.hash,
            'contents': self.contents,
            'uri': self.uri,
            'type': self.type,
            'certificate_uri': self.certificate_uri,
            'key': self.key,
            'account_id': self.account_id,
            'user_id': self.user_id
        }).encode("utf-8")

    @staticmethod
    def deserialize(data):
        try:
            if not isinstance(data, str):
                data = data.decode("utf-8")
            data = json.loads(data)
            if 'id' not in data:
                raise ValueError("Missing 'id' field.")
            if 'contents' not in data:
                raise ValueError("Missing 'contents' field.")
            if 'uri' not in data:
                raise ValueError("Missing 'uri' field.")
            if 'type' not in data:
                raise ValueError("Missing 'type' field.")
            order = Order.query.get(data['id'])
            order.contents = data['contents']
            order.uri = data['uri']
            order.type = data['type']
            order.certificate_uri = data['certificate_uri'] if data['certificate_uri'] else None
            order.key = data['key'] if data['key'] else None
            return order
        except (TypeError, ValueError, AttributeError) as e:
            raise IOError("Invalid account structure: {}".format(e))

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

    def serialize(self):
        return json.dumps({
            'id': self.id,
            'fingerprint': self.fingerprint,
            'expiry': self.expiry,
            'body': self.body,
            'csr': self.csr,
            'intermediate': self.intermediate,
            'chain': self.chain,
            'key': self.private_key,
            'order_id': self.order_id,
            'user_id': self.user_id,
            'status': self.status
        }).encode("utf-8")