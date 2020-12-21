from certifire import get_version, db
from certifire import database
from .acme import AcmeV2
from certifire.errors import CertifireError
from .errors import AccountAlreadyExistsError
from .crypto import (
    generate_rsa_key,
    load_private_key,
)
from .helpers import confirm
from .models import Account

import os


def register(server, email, key_file=None, user_id=1):
    print("Certifire {}. ACME account registration.\n\n".format(
        get_version()))

    check = database.get_all(Account,email,'email')
    if check:
        for act in check:
            if server in act.act_uri and user_id==act.user_id:
                print("Account {} exists for given email {}.".format(act.act_uri,email))
                return False, act.id
    # Load key or generate
    if key_file:
        try:
            with open(key_file, 'rb') as f:
                account = Account(key=load_private_key(f.read()), email=email)
        except (ValueError, AttributeError, TypeError, IOError) as e:
            print("ERROR: Couldn't read key.")
            raise CertifireError(e)
    else:
        account = Account(key=generate_rsa_key(4096), email=email, user_id=user_id, server=server)

    # Register
    acmev2 = AcmeV2(server, account)
    try:
        terms_agreed = False
        terms_agreed = True
        acmev2.register(email, terms_agreed)
        print("Account {} created.".format(account.uri))
    except IOError as e:
        print("ERROR: Registration failed due to a connection or request "
              "error.")
        raise CertifireError(e)

    account.finalize()
    db.session.add(account)
    db.session.commit()
    return True, account.id
