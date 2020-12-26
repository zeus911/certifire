import binascii
import datetime
import json
import time
from threading import Thread

import josepy as jose
from certifire import config, database
from certifire.plugins.acme import crypto
from certifire.plugins.acme.models import Account, Certificate, Order
from certifire.plugins.dns_providers.plugin import get_dns_provider
from retrying import retry

from acme import challenges, errors, messages
from acme.client import BackwardsCompatibleClientV2, ClientNetwork
from acme.errors import TimeoutError
from acme.messages import Error as AcmeError
from acme.messages import Order as acmeOrder
from acme.messages import OrderResource, RegistrationResource


class AcmeHandler:
    def __init__(self, account_id=None):
        if account_id:
            self.account = Account.query.get(account_id)

            self.key = jose.JWKRSA(key=crypto.load_private_key(
                self.account.key.encode("utf8")))

            regr = RegistrationResource.from_json(json.loads(self.account.contents))
            net = ClientNetwork(self.key, account=regr)
            self.client = BackwardsCompatibleClientV2(
                net, self.key, self.account.directory_uri)
        else:
            print("Setup ACME Account")

    def setup_acme_account(self, user_id, email=None, server=None, rsa_key=None,
                           organization: str = None,
                           organizational_unit: str = None,
                           country: str = None,
                           state: str = None,
                           location: str = None):
        if not email:
            email = config.CERTIFIRE_EMAIL
        if not server:
            server = config.LETS_ENCRYPT_PRODUCTION
        if not rsa_key:
            rsa_key = crypto.generate_rsa_key()

        account = Account(user_id, email, server,
                          organization=organization,
                          organizational_unit=organizational_unit,
                          country=country,
                          state=state,
                          location=location)
        key = jose.JWKRSA(key=rsa_key)
        net = ClientNetwork(key, account=None, timeout=3600)
        client = BackwardsCompatibleClientV2(
            net, key, account.directory_uri)
        registration = client.new_account_and_tos(
            messages.NewRegistration.from_data(email=email)
        )
        account.key = crypto.export_private_key(
            rsa_key).decode("utf-8")
        account.uri = registration.uri
        account.contents = json.dumps(registration.to_json())

        database.add(account)
        self.account = account
        self.key = key
        self.client = client
        return account

    def deregister_acme_account(self):
        regr = RegistrationResource.from_json(json.loads(self.account.contents))
        updated_regr = self.client.deactivate_registration(regr)
        if updated_regr.body.status == 'deactivated':
            return True
        return False

    def generate_csr(self, domains: list,
                     email: str = None,
                     organization: str = None,
                     organizational_unit: str = None,
                     country: str = None,
                     state: str = None,
                     location: str = None):
        csr_config = {
            "domains": domains,
            "owner": email if email else self.account.email,
            "organization": organization if organization else self.account.organization,
            "organizational_unit": organizational_unit if organizational_unit else self.account.organizational_unit,
            "country": country if country else self.account.country,
            "state": state if state else self.account.state,
            "location": location if location else self.account.location
        }

        csr_pem, key = crypto.create_csr(csr_config)
        return csr_pem, key


class AcmeDnsHandler(AcmeHandler):

    def get_pending_challenges(self, order):
        pending_challenges = {}
        for authz in order.authorizations:
            for challenge in authz.body.challenges:
                if challenge.typ == 'dns-01':
                    if challenge.status.name == 'pending':
                        print("Pending challenge: TXT {} for domain {}".format(
                            challenge.validation(self.key), authz.body.identifier.value))
                        pending_challenges[authz.body.identifier.value] = challenge
                    elif challenge.status.name == 'valid':
                        print("{} already validated, expires: {}".format(
                            authz.body.identifier.value, authz.body.expires))

        return pending_challenges
    
    def get_orderResource(self,order_id):
        order_db = Order.query.get(order_id)
        order = acmeOrder.from_json(json.loads(order_db.contents)['body'])
        orderr = OrderResource.from_json(json.loads(order_db.contents))
        authorizations = []
        for url in order.authorizations:
            authorizations.append(self.client._authzr_from_response(self.client._post_as_get(url), uri=url))
        return orderr.update(authorizations=authorizations)
        

    # @retry(stop_max_attempt_number=5, wait_fixed=10)
    def create_order(self, csr_pem, provider, order_id, reissue=False):
        order_db = Order.query.get(order_id)
        if order_db.status == 'revoked' and not reissue:
            print("Cannot issue for order with revoked certificate {}".format(order_db.resolved_cert_id))
            return order_db.resolved_cert_id
        
        if order_db.status == 'valid' and reissue:
            print("Revoking existing certificate {}".format(order_db.resolved_cert_id))
            self.revoke_certificate(order_db.resolved_cert_id)

        order = self.client.new_order(csr_pem)
        pending_challenges = self.get_pending_challenges(order)

        if not pending_challenges:
            if reissue:
                deadline = datetime.datetime.now() + datetime.timedelta(seconds=10)
                final_order = self.client.poll_and_finalize(order, deadline)
                order_db.contents = json.dumps(final_order.to_json())
                order_db.status = 'ready'
                database.add(order_db)
                cert_id = self.issue_certificate(final_order, order_id)

                return cert_id

            print("No pending challenges, reusing existing order")
            orderr = self.get_orderResource(order_id)
            if orderr.fullchain_pem is not None:
                if order_db.resolved_cert_id:
                    print("Certificate already issued")
                    return order_db.resolved_cert_id
                else:
                    print("Generating Certificate")
                    return self.issue_certificate(orderr, order_id)
            else:
                print("Reissuing certificate")

        order_db.uri = order.uri
        order_db.contents = json.dumps(order.to_json())
        database.add(order_db)

        dns = get_dns_provider(provider)

        change_ids = []
        print("Writing DNS Records")
        for domain, challenge in pending_challenges.items():
            change_id = dns.create_dns_record(
                domain, challenge.validation(self.key))
            change_ids.append(change_id)

        for change_id in change_ids:
            print("Waiting for DNS Change: {}".format(change_id))
            dns.wait_for_change(change_id)

        for domain, challenge in pending_challenges.items():
            response = challenge.response(self.key)
            verified = response.simple_verify(
                challenge.chall, domain, self.key.public_key())
            if not verified:
                print("{} not verified".format(domain))
            
            res = self.client.answer_challenge(challenge, response)
            #time.sleep(5)
            print("Ansering challenge {} with response {}".format(
                challenge.validation(self.key), response.key_authorization))
            res = self.client.answer_challenge(challenge, response)
            print("Got response: {}".format(res.body.status.name))

        print("Finalizing order")
        deadline = datetime.datetime.now() + datetime.timedelta(seconds=10 *
                                                                len(pending_challenges))
        #final_order = self.client.finalize_order(order, deadline)
        final_order = self.client.poll_and_finalize(order, deadline)
        order_db.contents = json.dumps(final_order.to_json())
        order_db.status = 'ready'
        database.add(order_db)

        for domain, challenge in pending_challenges.items():
            dns.delete_dns_record(domain, challenge.validation(self.key))

        cert_id = self.issue_certificate(final_order, order_id)

        return cert_id

    def issue_certificate(self, final_order, order_id):
        order_db = Order.query.get(order_id)
        cert_db = Certificate(user_id=order_db.user_id, order_id=order_db.id, status='pending',
                              csr=order_db.csr, private_key=order_db.key)
        database.add(cert_db)

        pem_certificate, pem_chain = crypto.extract_cert_and_chain(
            final_order.fullchain_pem)
        certificate = crypto.load_pem_certificate(pem_certificate.encode())
        chain = crypto.load_pem_certificate(pem_chain.encode())

        cert_db.body = crypto.export_pem_certificate(
            certificate).decode('UTF-8')
        cert_db.chain = crypto.export_pem_certificate(
            certificate).decode('UTF-8')
        cert_db.chain += crypto.export_pem_certificate(chain).decode('UTF-8')
        cert_db.intermediate = crypto.export_pem_certificate(
            chain).decode('UTF-8')
        cert_db.expiry = certificate.not_valid_after.strftime(
            config.EXPIRATION_FORMAT)
        cert_db.fingerprint = binascii.hexlify(
            certificate.fingerprint(crypto.hashes.SHA256())).decode('ascii')

        print("Expires: {}".format(cert_db.expiry))
        print("SHA256: {}".format(cert_db.fingerprint))

        order_db.status = 'valid'
        cert_db.status = 'valid'
        order_db.resolved_cert_id = cert_db.id
        print("Resolved certificate id: {}".format(order_db.resolved_cert_id))
        database.add(order_db)
        database.add(cert_db)

        return cert_db.id
    
    def revoke_certificate(self, cert_id, delete=False):
        cert_db = Certificate.query.get(cert_id)
        order_db = Order.query.get(cert_db.order_id)
        
        if cert_db.status == 'revoked':
            status = "This certificate is already revoked"
            print(status)
            return False, status

        certificate = crypto.load_pem_certificate(cert_db.body.encode('ASCII'))
        print("Revoking certificate for:")
        for domain in crypto.get_certificate_domains(certificate):
            print("     {}".format(domain))
        
        certificate = crypto.load_cert_for_revoke(cert_db.body.encode('ASCII'))
        try:
            self.client.revoke(certificate,0)
            print("Certificate {} revoked.".format(cert_db.id))
            order_db.status = 'revoked'
            cert_db.status = 'revoked'
            database.add(order_db)
            if delete:
                print("Deleting certificate from database")
                database.delete(cert_db)
            else:
                database.add(cert_db)
            status = 'Revoked'
            print(status)
            return True, status
        except IOError:
            status = "Revoke failed"
            print(status)
            return False, status

