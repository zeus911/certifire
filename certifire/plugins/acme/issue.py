from certifire import get_version, config, db
from .acme import AcmeV2
from .authorize import update_order
from .crypto import (
    generate_rsa_key,
    load_private_key,
    export_private_key,
    create_csr,
    load_csr,
    export_csr_for_acme,
    load_pem_certificate,
    export_pem_certificate,
    strip_certificates,
)
from certifire.errors import CertifireError
from .models import Order, Certificate
from threading import Thread
import binascii
from cartola import fs, sysexits
from cryptography.hazmat.primitives.hashes import SHA256
import hashlib
import logging
import os
import sys

logger = logging.getLogger(__name__)

EXPIRATION_FORMAT = "%Y-%m-%d"


def issue(account, order, key_size, key_file=None,
          csr_file=None, output_path=None, must_staple=False, verbose=False):
    print("Certifire {}. Issue certificate.\n\n".format(
        get_version()))

    if order.status == 'Issued':
        return False, order.resolved_cert_id

    paths = config.paths
    orders_path = paths['orders']
    domains_hash = order.hash
    order_path = os.path.join(orders_path, domains_hash)
    order_file = os.path.join(order_path, "order.json")
    domains = order.domains.split(',')
    server = account.server
    user_id = order.user_id

    if not os.path.exists(orders_path):
        print(" ERROR: Orders path not found. Please run before: certifire authorize {}".format(" ".join(domains)))
        sys.exit(sysexits.EX_CANNOT_EXECUTE)
    else:
        if verbose:
            print("Orders path found at {}.".format(orders_path))

    if verbose:
        print("Searching order file {}.".format(order_file))

    if not os.path.exists(order_path):
        print(" ERROR: Order file not found. Please run before: certifire authorize {}".format(" ".join(domains)))
        sys.exit(sysexits.EX_CANNOT_EXECUTE)
    else:
        if verbose:
            print("Current order {} path found at orders path.\n".format(
                domains_hash))

    acme = AcmeV2(server, account)
    order = Order.deserialize(fs.read(order_file))
    if order.contents['status'] == "pending":
        if verbose:
            print("Querying ACME server for current status.")
        server_order = acme.query_order(order)
        order.contents = server_order.contents
        update_order(order, order_file)
        if order.contents['status'] in ["pending", "invalid"]:
            print(" ERROR: Order not ready or invalid. Please re-run: certifire"
                  " authorize {}.".format(" ".join(domains)))
            sys.exit(sysexits.EX_CANNOT_EXECUTE)
    elif order.contents['status'] == "invalid":
        print(" ERROR: Invalid order. Please re-run: certifire authorize "
              "{}.".format(" ".join(domains)))
        sys.exit(sysexits.EX_CANNOT_EXECUTE)

    if not output_path or output_path == '.':
        output_path = os.path.join(orders_path, domains_hash)

    # Load key if given
    if key_file:
        try:
            with open(key_file, 'rb') as f:
                certificate_key = load_private_key(f.read())
            order.key = export_private_key(certificate_key).decode('ascii')
            update_order(order, order_file)
        except (ValueError, AttributeError, TypeError, IOError) as e:
            print("ERROR: Couldn't read certificate key.")
            raise CertifireError(e)
    else:
        certificate_key = None

    # Load CSR or generate
    if csr_file:
        try:
            with open(csr_file, 'rb') as f:
                csr = export_csr_for_acme(load_csr(f.read()))
        except (ValueError, AttributeError, TypeError, IOError) as e:
            print("ERROR: Couldn't read CSR.")
            raise CertifireError(e)
    else:
        # Generate key
        if not key_file:
            if order.key is None:
                print("Generating a {} bit RSA key. This might take a "
                      "second.".format(key_size))
                certificate_key = generate_rsa_key(key_size)
                print("  Key generated.")
                order.key = export_private_key(certificate_key).decode('ascii')
                update_order(order, order_file)
                print("  Order updated with generated key.")
            else:
                print("Previous RSA key found in the order. Loading the key.")
                certificate_key = load_private_key(order.key.encode('ascii'))

        csr = create_csr(certificate_key, domains, must_staple=must_staple)

    certificate = Certificate(private_key=order.key, csr=export_csr_for_acme(csr), order_id=order.id, user_id=user_id, status='Pending')
    db.session.add(certificate)
    db.session.commit()
    Thread(target=issue_after_return, args=(
    acme, order_file, domains, domains_hash, csr, output_path, certificate.id, verbose)).start()
    return True, certificate.id

def issue_after_return(acme, order_file, domains, domains_hash, csr, output_path, cert_id, verbose=False):
    order = Order.deserialize(fs.read(order_file))
    try:
        logger.info("Requesting certificate issuance...")
        if order.contents['status'] == "ready":
            final_order = acme.finalize_order(order, csr)
            order.contents = final_order
            update_order(order, order_file)
            if final_order['status'] in ["processing", "valid"]:
                if verbose:
                    print("  Order {} finalized. Certificate is being "
                          "issued.".format(domains_hash))
            else:
                print(" ERROR: Order not ready or invalid. Please re-run: "
                      "certifire authorize {}.".format(" ".join(domains)))
                sys.exit(sysexits.EX_CANNOT_EXECUTE)
        elif order.contents['status'] in ["valid", "processing"]:
            print("  Order {} is already processing or valid. Downloading "
                  "certificate.".format(domains_hash))
        else:
            print(" ERROR: Order not ready or invalid. Please re-run: certifire "
                  "authorize {}.".format(" ".join(domains)))
            sys.exit(sysexits.EX_CANNOT_EXECUTE)

        if order.certificate_uri is None:
            if verbose:
                print("  Checking order {} status.".format(domains_hash))
            fulfillment = acme.await_for_order_fulfillment(order)
            if fulfillment['status'] == "valid":
                order.contents = fulfillment
                update_order(order, order_file)
            else:
                print(" ERROR: Order not ready or invalid. Please re-run: "
                      "certifire authorize {}.".format(" ".join(domains)))
                sys.exit(sysexits.EX_CANNOT_EXECUTE)
        else:
            print("  We already know the certificate uri for order {}. "
                  "Downloading certificate.".format(domains_hash))

        result = acme.download_order_certificate(order)

        logger.info("  Certificate downloaded.")
    except IOError as e:
        print("Connection or service request failed. Aborting.")
        raise CertifireError(e)

    try:
        certificates = strip_certificates(result.content)
        certificate = load_pem_certificate(certificates[0])
        certdb = Certificate.query.get(cert_id)

        # Print some neat info
        print("  Expires: {}".format(certificate.not_valid_after.strftime(
            EXPIRATION_FORMAT)))
        print("   SHA256: {}".format(binascii.hexlify(
            certificate.fingerprint(SHA256())).decode('ascii')))
        
        certdb.expiry = certificate.not_valid_after.strftime(EXPIRATION_FORMAT)
        certdb.fingerprint = binascii.hexlify(certificate.fingerprint(SHA256())).decode('ascii')

        # Write the key, certificate and full chain
        os.makedirs(output_path, exist_ok=True)
        cert_path = os.path.join(output_path, domains[0] + '.crt')
        chain_path = os.path.join(output_path, domains[0] + '.chain.crt')
        intermediate_path = os.path.join(output_path,
                                         domains[0] + '.intermediate.crt')
        key_path = os.path.join(output_path, domains[0] + '.pem')

        if order.key is not None:
            certdb.key = order.key.encode('ascii')
            with open(key_path, 'wb') as f:
                os.chmod(key_path, 0o600)
                f.write(order.key.encode('ascii'))
                print("\n  Wrote key to {}".format(f.name))

        certdb.body = export_pem_certificate(certificate).decode('UTF-8')
        with open(cert_path, 'wb') as f:
            f.write(export_pem_certificate(certificate))
            print("  Wrote certificate to {}".format(f.name))

        certdb.chain = export_pem_certificate(certificate).decode('UTF-8')
        with open(chain_path, 'wb') as f:
            f.write(export_pem_certificate(certificate))
            if len(certificates) > 1:
                certdb.chain += export_pem_certificate(load_pem_certificate(certificates[1])).decode('UTF-8')
                f.write(export_pem_certificate(load_pem_certificate(
                    certificates[1])))
            print("  Wrote certificate with intermediate to {}".format(f.name))

        if len(certificates) > 1:
            certdb.intermediate = export_pem_certificate(load_pem_certificate(certificates[1])).decode('UTF-8')
            with open(intermediate_path, 'wb') as f:
                f.write(export_pem_certificate(load_pem_certificate(
                    certificates[1])))
                print("  Wrote intermediate certificate to {}".format(f.name))
        
        order.status = 'Issued'
        certdb.status = 'Valid'
        order.resolved_cert_id = certdb.id
        db.session.add(order)
        db.session.add(certdb)
        db.session.commit()
    except IOError as e:
        print("  ERROR: Failed to write certificate or key. Going to print "
              "them for you instead.")
        if order.key is not None:
            for line in order.key.split('\n'):
                print("ERROR: {}".format(line))
        for line in export_pem_certificate(
                certificate).decode('ascii').split('\n'):
            print("ERROR: {}".format(line))
        raise CertifireError(e)
