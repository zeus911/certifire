from flask import abort, g, jsonify, request, url_for
from sqlalchemy import Column, Integer, Text, String

from certifire import app, auth, db
from certifire.utils import Vault


class Certificate_old(db.Model):
    __tablename__ = "certificates_old"
    id = Column(Integer, primary_key=True)
    external_id = Column(String(128))
    body = Column(Text())
    intermediate = Column(Text())
    chain = Column(Text())
    csr = Column(Text())
    private_key = Column(Text())
    expiry = Column(String(12))
    fingerprint = Column(Text())
