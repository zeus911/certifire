import logging
import os
from certifire import get_version, config, db
from .acme import AcmeV2
from certifire.errors import CertifireError
from .crypto import (
    load_pem_certificate,
    get_certificate_domains
)
from .helpers import confirm
from .models import Order, Account
from cartola import fs

logger = logging.getLogger(__name__)


def revoke(certdb):
    print("Certifire {}. Revoke Certificate.\n\n".format(
        get_version()))

    order = Order.query.get(certdb.order_id)
    if order.status == 'Revoked':
        return False

    paths = config.paths
    orders_path = paths['orders']
    domains_hash = order.hash
    order_path = os.path.join(orders_path, domains_hash)
    order_file = os.path.join(order_path, "order.json")
    order = Order.deserialize(fs.read(order_file))

    account = Account.query.get(order.account_id)
    account.initialize()
    # Load the certificate
    try:
        certificate = load_pem_certificate(certdb.body.encode('ASCII'))
    except IOError as e:
        print("ERROR: Couldn't read the certificate.")
        raise CertifireError(e)

    # Confirm
    print("Revoking certificate for:")
    for domain in get_certificate_domains(certificate):
        print("     {}".format(domain))

    # Revoke.
    acme = AcmeV2(account.server, account)
    try:
        acme.revoke_certificate(certificate)
    except IOError as e:
        raise CertifireError(e)

    print("Certificate revoked.")
    order.status = 'Revoked'
    certdb.status = 'Revoked'
    db.session.add(order)
    db.session.add(certdb)
    db.session.commit()
    return True
