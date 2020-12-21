from cryptography.fernet import Fernet, MultiFernet
from sqlalchemy import types

class Vault(types.TypeDecorator):
    """
    A custom SQLAlchemy column type that transparently handles encryption.

    This uses the MultiFernet from the cryptography package to facilitate
    key rotation. That class handles encryption and signing.

    Fernet uses AES in CBC mode with 128-bit keys and PKCS7 padding. It
    uses HMAC-SHA256 for ciphertext authentication. Initialization
    vectors are generated using os.urandom().
    """

    # required by SQLAlchemy. defines the underlying column type
    impl = types.LargeBinary

    def process_bind_param(self, value, dialect):
        """
        Encrypt values on the way into the database.

        MultiFernet.encrypt uses the first key in the list.
        """

        # we assume that the user's keys are already Fernet keys (32 byte
        # keys that have been base64 encoded).
        self.keys = [Fernet(key) for key in get_keys()]

        if not value:
            return

        # ensure bytes for fernet
        if isinstance(value, str):
            value = value.encode("utf-8")

        return MultiFernet(self.keys).encrypt(value)

    def process_result_value(self, value, dialect):
        """
        Decrypt values on the way out of the database.

        MultiFernet tries each key until one works.
        """

        # we assume that the user's keys are already Fernet keys (32 byte
        # keys that have been base64 encoded).
        self.keys = [Fernet(key) for key in get_keys()]

        # if the value is not a string we aren't going to try to decrypt
        # it. this is for the case where the column is null
        if not value:
            return

        return MultiFernet(self.keys).decrypt(value).decode("utf8")
