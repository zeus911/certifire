import hashlib
from threading import Thread

from certifire import config, database, db
from certifire.plugins.acme import crypto
from certifire.plugins.acme.handlers import AcmeDnsHandler
from certifire.plugins.acme.models import Account, Certificate, Order


def register(user_id=1, email: str = None, server: str = None, rsa_key=None,
             organization: str = None,
             organizational_unit: str = None,
             country: str = None,
             state: str = None,
             location: str = None):

    email = email if email else config.CERTIFIRE_EMAIL
    server = server if server else config.LETS_ENCRYPT_PRODUCTION
    organization = organization if organization else config.CERTIFIRE_ORGANIZATION
    organizational_unit = organizational_unit if organizational_unit else config.CERTIFIRE_ORGANIZATIONAL_UNIT
    country = country if country else config.CERTIFIRE_COUNTRY
    state = state if state else config.CERTIFIRE_STATE
    location = location if location else config.CERTIFIRE_LOCATION

    check = database.get_all(Account, email, 'email')
    for act in check:
        if email == act.email and server == act.server and user_id == act.user_id:
            print("Account {} exists for given email {}.".format(act.uri, email))
            return False, act.id

    acme = AcmeDnsHandler()
    account = acme.setup_acme_account(user_id, email, server, rsa_key,
                                      organization, organizational_unit, country, state, location)
    print("Account {} created for given email {}.".format(
        account.uri, account.email))
    return True, account.id

def deregister(user_id:int, account_id: int):
    account = Account.query.get(account_id)
    if account.user_id != user_id:
        print("This account does not belong to this user")
        return False, account_id
    
    print("Deleting ACME account and revoking all certificates associated with it")
    orders = database.get_all(Order, account_id, 'account_id')
    for order in orders:
        if order.resolved_cert_id:
            revoke_certificate(account_id, order.resolved_cert_id)
    
    print("Deregistering acme account with email: {}".format(account.email))
    acme = AcmeDnsHandler(account.id)
    if acme.deregister_acme_account():
        database.delete(account)
        print("Done")

def create_order(account_id: int,
                 domains: list,
                 type: str = None,
                 provider: str = None,
                 email: str = None,
                 organization: str = None,
                 organizational_unit: str = None,
                 country: str = None,
                 state: str = None,
                 location: str = None,
                 reissue: bool = False,
                 csr: str = None,
                 key: str = None):

    account = Account.query.get(account_id)
    if not account:
        return False, 0

    type = type if type else config.DEFAULT_AUTH_TYPE
    provider = provider if provider else config.DEFAULT_DNS
    email = email if email else account.email
    organization = organization if organization else account.organization
    organizational_unit = organizational_unit if organizational_unit else account.organizational_unit
    country = country if country else account.country
    state = state if state else account.state
    location = location if location else account.location

    if provider not in config.VALID_DNS_PROVIDERS:
        print("Invalid DNS Provider")
        return False, 0

    acme = AcmeDnsHandler(account.id)

    domains_hash = hashlib.sha256(
        "_".join(domains).encode("ascii")).hexdigest()
    check = database.get_all(Order, domains_hash, 'hash')
    for order in check:
        if order.email == email and order.type == type and order.account_id == account.id:
            print("Order {} exists for given email: {} and account_id: {}.".format(
                order.uri, email, account.id))
            #acme_order = acme.create_order(order.csr, order.provider, order.id)
            Thread(target=acme.create_order, args=(
                order.csr, order.provider, order.id, reissue)).start()
            return False, order.id

    if type == 'dns':
        if not csr or key:
            csr, key = acme.generate_csr(
                domains, email, organization, organizational_unit, country, state, location)

        order = Order(domains, type, provider, account.id, account.user_id, domains_hash,
                      csr, key, email, organization, organizational_unit, country, state, location)
        database.add(order)

        #acme_order = acme.create_order(csr, provider, order.id)
        Thread(target=acme.create_order, args=(
            csr, provider, order.id)).start()
        return True, order.id


def reorder(account_id: int, order_id: int):
    account = Account.query.get(account_id)
    order_db = Order.query.get(order_id)

    if order_db.account_id != account_id:
        print("This order does not belong to this account")
        return False, order_id

    acme = AcmeDnsHandler(account.id)
    Thread(target=acme.create_order, args=(order_db.csr,
                                           order_db.provider, order_db.id, True)).start()
    return True, order_db.id


def revoke_certificate(account_id: int, cert_id: int, delete: bool = False):
    account = Account.query.get(account_id)
    cert_db = Certificate.query.get(cert_id)
    order_db = Order.query.get(cert_db.order_id)

    if cert_db.status == 'revoked':
        status = "This certificate is already revoked"
        print(status)
        return False, status

    if order_db.account_id != account_id:
        status = "This certificate does not belong to this account"
        print(status)
        return False, status

    acme = AcmeDnsHandler(account.id)
    return acme.revoke_certificate(cert_id, delete)
