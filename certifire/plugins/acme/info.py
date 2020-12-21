from certifire import get_version
from .acme import AcmeV2
from certifire.errors import CertifireError
import logging
import os

logger = logging.getLogger(__name__)


def info(server, account, paths):
    acme_v2 = AcmeV2(server, account)
    print("Certifire {}. Account Info"
          "\n\n".format(get_version()))

    try:
        print("Requesting account data...\n")

        response = acme_v2.get_registration()
        print("  Account contacts:")
        for contact in response['contact']:
            print("    {}".format(contact[7:]))
        if "createdAt" in response:
            print("  Creation: {}".format(response['createdAt']))
        if "initialIp" in response:
            print("  Initial Ip: {}".format(response['initialIp']))
        if "key" in response:
            print("  Key Data:")
            print("    Type: {}".format(response['key']['kty']))
            print("    Public key (part I) n: {}".format(
                response['key']['n']))
            print("    Public key (part II) e: {}\n".format(
                response['key']['e']))
        else:
            print("    WARNING: Server won't return your key information.")
        print("    Private key stored at {}".format(
            os.path.join(paths['current'], "account.json")))
    except IOError as e:
        raise CertifireError(e)
