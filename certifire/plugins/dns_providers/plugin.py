from certifire.errors import UnknownProvider
from certifire.plugins.dns_providers.common import BaseDns
from certifire.plugins.dns_providers.route53 import Route53Dns

def get_dns_provider(type) -> BaseDns:
        if type == "route53":
            print("Initialized route53 DNS Plugin")
            return Route53Dns()
        else:
            raise UnknownProvider("No such DNS provider: {}".format(type))
