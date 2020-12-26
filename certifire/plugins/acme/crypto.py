import base64
import datetime
import json
import logging
import re

import josepy as jose
import OpenSSL
from certifire import config
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.ec import \
    EllipticCurvePrivateKey
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey, generate_private_key)
from cryptography.hazmat.primitives.serialization import (Encoding,
                                                          NoEncryption,
                                                          PrivateFormat,
                                                          load_pem_private_key)
from cryptography.x509 import NameOID

logger = logging.getLogger(__name__)


def jose_b64(data):
    """
    Encodes data with JOSE/JWS base 64 encoding.
    """
    return base64.urlsafe_b64encode(data).decode('ascii').replace('=', '')


def generate_rsa_key(size=4096):
    """
    Generates a new RSA private key.
    """
    return generate_private_key(65537, size, default_backend())


def export_private_key(key):
    """
    Exports a private key in OpenSSL PEM format.
    """
    return key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption())


def load_private_key(data):
    """
    Loads a PEM-encoded private key.
    """
    key = load_pem_private_key(data, password=None, backend=default_backend())
    if not isinstance(key, (RSAPrivateKey, EllipticCurvePrivateKey)):
        raise ValueError("Key is not a private RSA or EC key.")
    elif isinstance(key, RSAPrivateKey) and key.key_size < 2048:
        raise ValueError("The key must be 2048 bits or longer.")

    return key


def export_csr_for_acme(csr):
    """
    Exports a X.509 CSR for the ACME protocol (JOSE Base64 DER).
    """
    return export_certificate_for_acme(csr)


def load_csr(data):
    """
    Loads a PEM X.509 CSR.
    """
    return x509.load_pem_x509_csr(data, default_backend())


def generate_header(account_key):
    """
    Creates a new request header for the specified account key.
    """
    numbers = account_key.public_key().public_numbers()
    e = numbers.e.to_bytes((numbers.e.bit_length() // 8 + 1), byteorder='big')
    n = numbers.n.to_bytes((numbers.n.bit_length() // 8 + 1), byteorder='big')
    if n[0] == 0:  # for strict JWK
        n = n[1:]
    return {
        'alg': 'RS256',
        'jwk': {
            'kty': 'RSA',
            'e': jose_b64(e),
            'n': jose_b64(n),
        },
    }


def generate_jwk_thumbprint(account_key):
    """
    Generates a JWK thumbprint for the specified account key.
    """
    jwk = generate_header(account_key)['jwk']
    as_json = json.dumps(jwk, sort_keys=True, separators=(',', ':'))

    sha256 = hashes.Hash(hashes.SHA256(), default_backend())
    sha256.update(as_json.encode('utf-8'))

    return jose_b64(sha256.finalize())


def create_csr(csr_config, private_key=None):
    """
    Given a list of domains create the appropriate csr
    for those domains

    :param csr_config:
    """
    if not private_key:
        private_key = generate_rsa_key(4096)

    builder = x509.CertificateSigningRequestBuilder()
    name_list = [x509.NameAttribute(
        x509.OID_COMMON_NAME, csr_config["domains"][0])]

    name_list.append(
        x509.NameAttribute(x509.OID_EMAIL_ADDRESS, csr_config["owner"])
    )
    if "organization" in csr_config and csr_config["organization"].strip():
        name_list.append(
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME,
                               csr_config["organization"])
        )
    if (
        "organizational_unit" in csr_config
        and csr_config["organizational_unit"].strip()
    ):
        name_list.append(
            x509.NameAttribute(
                x509.OID_ORGANIZATIONAL_UNIT_NAME, csr_config["organizational_unit"]
            )
        )
    if "country" in csr_config and csr_config["country"].strip():
        name_list.append(
            x509.NameAttribute(x509.OID_COUNTRY_NAME, csr_config["country"])
        )
    if "state" in csr_config and csr_config["state"].strip():
        name_list.append(
            x509.NameAttribute(
                x509.OID_STATE_OR_PROVINCE_NAME, csr_config["state"])
        )
    if "location" in csr_config and csr_config["location"].strip():
        name_list.append(
            x509.NameAttribute(x509.OID_LOCALITY_NAME, csr_config["location"])
        )

    if "domains" in csr_config:
        san = x509.SubjectAlternativeName(
            [x509.DNSName(domain) for domain in csr_config["domains"]])
        builder.add_extension(san, critical=True)

    builder = builder.subject_name(
        x509.Name(name_list)).add_extension(san, critical=False)

    if csr_config.get("must_staple", False):
        ocsp_must_staple = x509.TLSFeature(
            features=[x509.TLSFeatureType.status_request])
        builder.add_extension(ocsp_must_staple, critical=False)

    extensions = csr_config.get("extensions", {})
    critical_extensions = ["basic_constraints", "sub_alt_names", "key_usage"]
    noncritical_extensions = ["extended_key_usage"]
    for k, v in extensions.items():
        if v:
            if k in critical_extensions:
                logger.debug(
                    "Adding Critical Extension: {0} {1}".format(k, v)
                )
                if k == "sub_alt_names":
                    if v["names"]:
                        builder = builder.add_extension(
                            v["names"], critical=True)
                else:
                    builder = builder.add_extension(v, critical=True)

            if k in noncritical_extensions:
                logger.debug("Adding Extension: {0} {1}".format(k, v))
                builder = builder.add_extension(v, critical=False)

    ski = extensions.get("subject_key_identifier", {})
    if ski.get("include_ski", False):
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                private_key.public_key()),
            critical=False,
        )

    request = builder.sign(private_key, hashes.SHA256(), default_backend())

    # serialize our private key and CSR
    private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        # would like to use PKCS8 but AWS ELBs don't like it
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")

    csr = request.public_bytes(
        encoding=serialization.Encoding.PEM).decode("utf-8")

    return csr, private_key


def load_der_certificate(data):
    """
    Loads a DER X.509 certificate.
    """
    return x509.load_der_x509_certificate(data, default_backend())


def load_pem_certificate(data):
    """
    Loads a PEM X.509 certificate.
    """
    return x509.load_pem_x509_certificate(data, default_backend())


def get_certificate_domain_name(cert):
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def get_certificate_domains(cert):
    """
    Gets a list of all Subject Alternative Names in the specified certificate.
    """
    for ext in cert.extensions:
        ext = ext.value
        if isinstance(ext, x509.SubjectAlternativeName):
            return ext.get_values_for_type(x509.DNSName)
    return []


def export_pem_certificate(cert):
    """
    Exports a X.509 certificate as PEM.
    """
    return cert.public_bytes(Encoding.PEM)


def export_certificate_for_acme(cert):
    """
    Exports a X.509 certificate for the ACME protocol (JOSE Base64 DER).
    """
    return jose_b64(cert.public_bytes(Encoding.DER))


def strip_certificates(data):
    p = re.compile("-----BEGIN CERTIFICATE-----\n(?s).+?"
                   "-----END CERTIFICATE-----\n")
    stripped_data = []
    for cert in p.findall(data.decode()):
        stripped_data.append(cert.encode())
    return stripped_data


def extract_cert_and_chain(fullchain_pem):
    pem_certificate = OpenSSL.crypto.dump_certificate(
        OpenSSL.crypto.FILETYPE_PEM,
        OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, fullchain_pem
        ),
    ).decode()

    if config.IDENTRUST_CROSS_SIGNED_LE_ICA \
            and datetime.datetime.now() < datetime.datetime.strptime(
            config.IDENTRUST_CROSS_SIGNED_LE_ICA_EXPIRATION_DATE, '%d/%m/%y'):
        pem_certificate_chain = config.IDENTRUST_CROSS_SIGNED_LE_ICA
    else:
        pem_certificate_chain = fullchain_pem[len(pem_certificate):].lstrip()

    return pem_certificate, pem_certificate_chain

def load_cert_for_revoke(key_pem, is_x509_cert=True):
    if is_x509_cert:
      pubkey = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, key_pem)
    else:
      pubkey = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, key_pem)
    return jose.ComparableX509(pubkey)
