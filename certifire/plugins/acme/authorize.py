from certifire import get_version, db, config
from .acme import AcmeV2
from .crypto import generate_jwk_thumbprint
from certifire.errors import CertifireError
from .models import Order
from certifire.plugins.dns_providers.route53 import Route53Dns

from cartola import fs, sysexits
from threading import Thread
import hashlib
import os
import sys
import time

R = Route53Dns()


def create_order(acme, domains, method, order_file, account_id, user_id, hash):
    order = acme.new_order(domains, method, account_id, user_id, hash)
    order.domains = ','.join(domains)
    update_order(order, order_file)
    return order


def update_order(order, order_file):
    db.session.add(order)
    db.session.commit()
    fs.write(order_file, order.serialize().decode())


def clean_challenge_file(challenge_file):
    try:
        os.remove(challenge_file)
    except:
        print("Couldn't delete challenge file {}".format(challenge_file))


def write_challenges(pending_challenges, method, current_path, files, account):
    if method == "dns":
        print(
            "\n  DNS verification required. Make sure these TXT records"
            " are in place:\n"
        )
        for challenge in pending_challenges:
            print(
                "    _acme-challenge.{}.  IN TXT  "
                '"{}"'.format(challenge.domain, challenge.key)
            )
            R.create_dns_record(challenge.domain, challenge.key)
    elif method == "http":
        print(
            "\n  HTTP verification required. Make sure these files are " "in place:\n"
        )
        for challenge in pending_challenges:
            token = challenge.contents["token"]
            # path sanity check
            assert token and os.path.sep not in token and "." not in token
            files.add(token)
            fs.write(
                os.path.join(current_path, token),
                "%s.%s" % (token, generate_jwk_thumbprint(account.key)),
            )
            print(
                "    http://{}/.well-known/acme-challenge/{}".format(
                    challenge.domain, token
                )
            )

        print(
            "\n  The necessary files have been written to the current " "directory.\n"
        )


def clean_challenges(challenges, method, files):
    if method == "dns":
        for challenge in challenges:
            R.delete_dns_record(challenge.domain, challenge.key)
    elif method == "http":
        # Clean up created files
        for path in files:
            try:
                os.remove(path)
            except:
                print("Couldn't delete http challenge file {}".format(path))


def authorize(
    account,
    domains,
    method,
    verbose=False,
    user_id=1,
):
    print("Certifire {}. Domain Authorization.\n\n".format(get_version()))

    paths = config.paths
    current_path = paths["current"]
    orders_path = paths["orders"]
    domains_hash = hashlib.sha256("_".join(domains).encode("ascii")).hexdigest()
    order_path = os.path.join(orders_path, domains_hash)
    order_file = os.path.join(order_path, "order.json")
    server = account.server
    account_id = account.id

    if not os.path.exists(orders_path):
        if verbose:
            print("Orders path not found creating it at {}." "".format(orders_path))
        os.mkdir(orders_path)
        os.chmod(orders_path, 0o770)
    else:
        if verbose:
            print("Orders path found at {}.".format(orders_path))

    if not os.path.exists(order_path):
        if verbose:
            print(
                "Current order {} path not found creating it at orders "
                "path.\n".format(domains_hash)
            )
        os.mkdir(order_path)
        os.chmod(order_path, 0o770)
    else:
        if verbose:
            print("Current order {} path found at orders path.\n".format(domains_hash))

    acme = AcmeV2(server, account)

    try:
        print("Authorizing {}.\n".format(", ".join(domains)))
        # Creating orders for domains if not existent
        if not os.path.exists(order_file):
            if verbose:
                print("  Order file not found creating it.")
            order = create_order(
                acme, domains, method, order_file, account_id, user_id, domains_hash
            )
        else:
            if verbose:
                print("  Found order file. Querying ACME server for current " "status.")
            order = Order.deserialize(fs.read(order_file))
            try:
                server_order = acme.query_order(
                    order, account_id, user_id, domains_hash
                )
                order.contents = server_order.contents
            except:
                print("    WARNING: Old order. Setting it as expired.\n")
                order.contents["status"] = "expired"
            update_order(order, order_file)

            if not order.expired and not order.invalid:
                if order.contents["status"] == "valid":
                    print(
                        "  Order is valid and expires at {}. Please run "
                        "the issue "
                        "command.\n".format(order.contents["expires"])
                    )
                    print(
                        "  {} domain(s) authorized. Let's Encrypt!".format(len(domains))
                    )
                    sys.exit(sysexits.EX_OK)
                else:
                    if verbose:
                        print(
                            "    Order still pending and expires "
                            "at {}.\n".format(order.contents["expires"])
                        )
            else:
                if order.invalid:
                    print(
                        "    WARNING: Invalid order, renewing it.\n    Just "
                        "continue with the authorization when all "
                        "verifications are in place.\n"
                    )
                else:
                    print("  WARNING: Expired order. Renewing order.\n")
                os.remove(order_file)
                order = create_order(
                    acme, domains, method, order_file, account_id, user_id, domains
                )
                update_order(order, order_file)

        pending_challenges = []

        for challenge in acme.get_order_challenges(order):
            print("  Requesting challenge for {}.".format(challenge.domain))
            if challenge.status == "valid":
                print(
                    "    {} is already authorized until {}.".format(
                        challenge.domain, challenge.expires
                    )
                )
                continue
            else:
                challenge_file = os.path.join(order_path, challenge.file_name)
                if verbose:
                    print(
                        "    Creating challenge file {}.\n".format(challenge.file_name)
                    )
                fs.write(challenge_file, challenge.serialize().decode())
                pending_challenges.append(challenge)

        # Quit if nothing to authorize
        if not pending_challenges:
            print("\nAll domains are already authorized, exiting.")
            return False, order.id

        Thread(
            target=authorize_after_return,
            args=(
                pending_challenges,
                method,
                current_path,
                acme,
                order_file,
                order_path,
                verbose,
                account,
                user_id,
                domains_hash,
            ),
        ).start()
        return True, order.id

    except IOError as e:
        print("A connection or service error occurred. Aborting.")
        raise CertifireError(e)


def authorize_after_return(
    pending_challenges,
    method,
    current_path,
    acme,
    order_file,
    order_path,
    verbose,
    account,
    user_id,
    domains_hash,
):
    account_id = account.id
    try:
        order = Order.deserialize(fs.read(order_file))
        files = set()
        write_challenges(pending_challenges, method, current_path, files, account)

        time.sleep(10)
        # Validate challenges
        done, failed, pending = set(), set(), set()
        for challenge in pending_challenges:
            print(
                "\n  {}: waiting for verification. Checking in 5 "
                "seconds.".format(challenge.domain)
            )
            response = acme.verify_order_challenge(challenge, 10, 1)
            if response["status"] == "valid":
                print(
                    "  {}: OK! Authorization lasts until {}.".format(
                        challenge.domain, challenge.expires
                    )
                )
                done.add(challenge.domain)
            elif response["status"] == "invalid":
                print(
                    "  {}: {} ({})".format(
                        challenge.domain,
                        response["error"]["detail"],
                        response["error"]["type"],
                    )
                )
                failed.add(challenge.domain)
                break
            else:
                print("{}: Pending!".format(challenge.domain))
                pending.add(challenge.domain)
                break

        challenge_file = os.path.join(order_path, challenge.file_name)
        # Print results
        if failed:
            print(
                "  {} domain(s) authorized, {} failed.".format(
                    len(done),
                    len(failed),
                )
            )
            print("  Authorized: {}".format(" ".join(done) or "N/A"))
            print("  Failed: {}".format(" ".join(failed)))
            print("  WARNING: The current order will be invalidated. " "Try again.")
            if verbose:
                print(
                    "    Deleting invalid challenge file {}.\n".format(
                        challenge.file_name
                    )
                )
            clean_challenge_file(challenge_file)
            os.remove(order_file)
            os.rmdir(order_path)
            order.status = 'Failed'
            db.session.add(order)
            db.session.commit()
            clean_challenges(pending_challenges, method, files)
            sys.exit(sysexits.EX_FATAL_ERROR)
        else:
            if pending:
                print(
                    "  {} domain(s) authorized, {} pending.".format(
                        len(done), len(pending)
                    )
                )
                print("  Authorized: {}".format(" ".join(done) or "N/A"))
                print("  Pending: {}".format(" ".join(pending)))
                print("  Try again.")
                sys.exit(sysexits.EX_CANNOT_EXECUTE)
            else:
                if verbose:
                    print(
                        "    Deleting valid challenge file {}.".format(
                            challenge.file_name
                        )
                    )
                clean_challenge_file(challenge_file)
                if verbose:
                    print("    Querying ACME server for current status.\n")
                server_order = acme.query_order(
                    order, account_id, user_id, domains_hash
                )
                order.contents = server_order.contents
                order.status = 'Authorized'
                update_order(order, order_file)
                print("  {} domain(s) authorized. Let's Encrypt!".format(len(done)))
        clean_challenges(pending_challenges, method, files)
        return order.id

    except IOError as e:
        print("A connection or service error occurred. Aborting.")
        raise CertifireError(e)
