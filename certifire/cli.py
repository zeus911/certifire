import argparse
import logging
import os
import sys

from certifire import app, auth, config, database, db, get_version
from certifire.errors import CertifireError
from certifire.plugins.acme import crypto
from certifire.plugins.acme.models import Account, Certificate, Order
from certifire.plugins.acme.plugin import (create_order, register, reorder,
                                           revoke_certificate)

logger = logging.getLogger(__name__)

# Text
DESCRIPTION = \
    """
Certifire {}.

Interact with ACME certification authorities such as Let's Encrypt.

No idea what you're doing? Register an account, authorize your domains and
issue a certificate or two. Call a command with -h for more instructions.
""".format(get_version())

DESCRIPTION_REGISTER = \
    """
Creates a new account key and registers on the server. The resulting --account
is saved in the database, and required for most other operations.

Takes email as required argument

You can pass arguments like organization, organizational_unit, country, state,
and location for csr generations from this account. if not provided, default
values from the config file will be used 

You can also pass your own RSA private key if needed
(Provide key size 2048 and above, otherwise the server won't accept it.)

You only have to do this once.
"""

DESCRIPTION_ISSUE = \
    """
Issues a certificate for one or more domains. Firstly, domains passed will be
authorized by the type of authentication specified. If dns authentication
is used, also provide the dns provider. If type and dns provider not passed,
default values will be used from the config file

Takes account_id as required argument

You can pass arguments like organization, organizational_unit, country, state,
and location for csr generations from this account. if not provided, default
values from the account will be used 

This will generate a new RSA key and CSR for you. But if you want, you can
bring your own with the --key-file and --csr-file attributes. 
(Provide key size 2048 and above, otherwise the server won't accept it.)

The resulting key and certificate are written into the database.
A chained certificate with the intermediate included is also written to databse.

(If you're passing your own CSR, the given domains can be whatever you want.)

Note that unlike many other certification authorities, ACME does not add a
non-www or www alias to certificates. If you want this to happen, add it
yourself. You need to authorize both as well.

Certificate issuance has a server-side rate limit. Don't overdo it.
"""

DESCRIPTION_REVOKE = \
    """
Revokes a certificate. The certificate must have been issued using the
current account.

Takes account_id and certificate_id as required arguments
"""

# Command handlers


def _register(args):
    key = None
    if args.key_file:
        with open(args.key_file, 'rb') as f:
            key = crypto.load_private_key(f.read())

    ret, act_id = register(
        user_id=1,
        email=args.email,
        server=args.server,
        rsa_key=key,
        organization=args.organization,
        organizational_unit=args.organizational_unit,
        country=args.country,
        state=args.state,
        location=args.location)

    if ret:
        print("Account created with account id: {}".format(act_id))
        print("Pass this account id for issue, revoke, etc...")
    else:
        print("Account with same email exists: account id: {}".format(act_id))


def _issue(args):
    key = None
    if args.key_file:
        with open(args.key_file, 'rb') as f:
            key = crypto.load_private_key(f.read())
    csr = None
    if args.csr_file:
        with open(args.csr_file, 'rb') as f:
            key = crypto.load_csr(f.read())

    ret, order_id = create_order(
        account_id=args.account,
        domains=args.domains,
        type=args.type,
        provider=args.provider,
        email=args.email,
        organization=args.organization,
        organizational_unit=args.organizational_unit,
        country=args.country,
        state=args.state,
        location=args.location,
        reissue=False,
        csr=csr,
        key=key)

    if ret:
        print("Order created with order id: {}".format(order_id))
    else:
        print("Order creation failed.")


def _revoke(args):
    certdb = Certificate.query.get(args.certificate)
    if not certdb:
        print("There is no such certificate {}".format(args.certificate))
        return

    order = Order.query.get(certdb.order_id)
    if not order:
        print("Order for this certificate not found")
        return

    revoke_certificate(order.account_id, certdb.id)


class Formatter(argparse.ArgumentDefaultsHelpFormatter,
                argparse.RawDescriptionHelpFormatter):
    pass


def certifire_main():
    parser = argparse.ArgumentParser(
        description=DESCRIPTION,
        formatter_class=Formatter,
    )
    subparsers = parser.add_subparsers()

    # Account creation
    register = subparsers.add_parser(
        'register',
        help="Create a new account and register",
        description=DESCRIPTION_REGISTER,
        formatter_class=Formatter,
    )
    register.add_argument('email', type=str, help="Account email address")
    register.add_argument('--server', '-i', help="ACME Server url")
    register.add_argument('--key-file', '-k',
                          help="Existing key file to use for the account")
    register.add_argument('--organization', '-o', help="Name of organization")
    register.add_argument('--organizational_unit', '-u',
                          help="Name of organizational unit")
    register.add_argument('--country', '-c', help="Name of country")
    register.add_argument('--state', '-s', help="Name of state")
    register.add_argument('--location', '-l', help="Name of location")
    register.set_defaults(func=_register)

    # Certificate issuance
    issue = subparsers.add_parser(
        'issue',
        help="Authorize and Request a new certificate",
        description=DESCRIPTION_ISSUE,
        formatter_class=Formatter,
    )
    issue.add_argument('--account', '-a',
                       help="The acme account id to use", required=True)
    issue.add_argument('domains',
                       help="One or more domain names to authorize", nargs='+')

    issue.add_argument('--type',
                       '-t',
                       help="Authorization type",
                       choices=('dns', 'http'),
                       default='dns')

    issue.add_argument('--provider',
                       '-p',
                       help="DNS Provider",
                       choices=config.VALID_DNS_PROVIDERS,
                       default=config.VALID_DNS_PROVIDERS[0])

    issue.add_argument('--key-file', '-k',
                       help="Existing key file to use for the certificate")

    issue.add_argument('--csr-file', help="Existing signing request to use")

    issue.add_argument('--email', '-e', help="email address for CSR")
    issue.add_argument('--organization', '-o', help="Name of organization")
    issue.add_argument('--organizational_unit', '-u',
                       help="Name of organizational unit")
    issue.add_argument('--country', '-c', help="Name of country")
    issue.add_argument('--state', '-s', help="Name of state")
    issue.add_argument('--location', '-l', help="Name of location")

    issue.set_defaults(func=_issue, ocsp_must_staple=False)

    # Certificate revocation
    revoke = subparsers.add_parser(
        'revoke',
        help="Revoke an issued certificate",
        description=DESCRIPTION_REVOKE,
        formatter_class=Formatter,
    )
    revoke.add_argument("certificate", help="The certificate id to revoke")
    revoke.add_argument('--account', '-a',
                        help="The acme account id to use", required=True)
    revoke.set_defaults(func=_revoke)

    # Version
    version = subparsers.add_parser("version", help="Show the version number")
    version.set_defaults(func=lambda *args: print(
        "certifire {}\n".format(get_version())))

    # Parse
    args = parser.parse_args()
    if not hasattr(args, 'func'):
        parser.print_help()
        sys.exit()

    # Set up logging
    root = logging.getLogger('certifire')
    root.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(message)s"))
    root.addHandler(handler)

    # Let's encrypt
    try:
        args.func(args)
    except CertifireError as e:
        if str(e):
            logger.error(e)
        sys.exit()
    except KeyboardInterrupt:
        logger.error("")
        logger.error("Interrupted.")
        sys.exit()
    except Exception as e:
        logger.error("Oops! An unhandled error occurred. Please file a bug.")
        logger.exception(e)
        sys.exit()


if __name__ == "__main__":
    certifire_main()
