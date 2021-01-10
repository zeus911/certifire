from os import path

import paramiko
from certifire import database, db, users
from paramiko.ssh_exception import (AuthenticationException,
                                    NoValidConnectionsError)
from sqlalchemy import Column, ForeignKey, Integer, String, Text


class Destination(db.Model):
    __tablename__ = "destinations"
    id = Column(Integer, primary_key=True)
    label = Column(String(32))
    ip = Column(String(32))
    host = Column(Text())
    port = Column(Integer())
    user = Column(Text())
    domains = Column(Text())
    password = Column(Text())
    ssh_priv_key = Column(Text())
    ssh_priv_key_pass = Column(Text())
    challengeDestinationPath = Column(Text())
    certDestinationPath = Column(Text())
    exportFormat = Column(Text())

    user_id = Column(Integer, ForeignKey("users.id"))

    def __init__(self, user_id, host, port=22, user='root', password=None,
                 ssh_priv_key=None, ssh_priv_key_pass=None, challengeDestinationPath='/var/www/html',
                 certDestinationPath='/etc/nginx/certs', exportFormat="NGINX"):
        self.user_id = user_id
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.ssh_priv_key = ssh_priv_key
        self.ssh_priv_key_pass = ssh_priv_key_pass
        self.challengeDestinationPath = challengeDestinationPath
        self.certDestinationPath = certDestinationPath
        self.exportFormat = exportFormat
        self.create()

    def __repr__(self):
        return "Destination(label={label})".format(label=self.id)

    @staticmethod
    def get_option(name, options):
        for o in options:
            if o.get("name") == name:
                return o.get("value", o.get("default"))

    def create(self):
        return database.create(self)

    def update(self, user_id=None, host=None, port=None, user=None, password=None,
               ssh_priv_key=None, ssh_priv_key_pass=None, challengeDestinationPath=None,
               certDestinationPath=None, exportFormat=None):
        self.user_id = user_id if user_id else self.user_id
        self.host = host if host else self.host
        self.port = port if port else self.port
        self.user = user if user else self.user
        self.password = password if password else self.password
        self.ssh_priv_key = ssh_priv_key if ssh_priv_key else self.ssh_priv_key
        self.ssh_priv_key_pass = ssh_priv_key_pass if ssh_priv_key_pass else self.ssh_priv_key_pass
        self.challengeDestinationPath = challengeDestinationPath if challengeDestinationPath else self.challengeDestinationPath
        self.certDestinationPath = certDestinationPath if certDestinationPath else self.certDestinationPath
        self.exportFormat = exportFormat if exportFormat else self.exportFormat
        database.update(self)

    def delete(self):
        database.delete(self)

    def open_sftp_connection(self):
        host = self.host
        port = self.port
        user = self.user
        password = self.password
        ssh_priv_key = self.ssh_priv_key
        ssh_priv_key_pass = self.ssh_priv_key_pass

        # delete files
        try:
            print(
                "Connecting to {0}@{1}:{2}".format(user, host, port)
            )
            ssh = paramiko.SSHClient()

            # allow connection to the new unknown host
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            # open the ssh connection
            if password:
                print("Using password")
                ssh.connect(host, username=user, port=port, password=password)
            elif ssh_priv_key:
                print("Using RSA private key")
                pkey = paramiko.RSAKey.from_private_key_file(
                    ssh_priv_key, ssh_priv_key_pass
                )
                ssh.connect(host, username=user, port=port, pkey=pkey)
            else:
                print(
                    "No password or private key provided. Can't proceed"
                )
                raise AuthenticationException

            # open the sftp session inside the ssh connection
            return ssh.open_sftp(), ssh

        except AuthenticationException as e:
            print("ERROR in {0}: {1}".format(e.__class__, e))
            raise AuthenticationException(
                "Couldn't connect to {0}, due to an Authentication exception.")
        except NoValidConnectionsError as e:
            print("ERROR in {0}: {1}".format(e.__class__, e))
            raise NoValidConnectionsError(
                "Couldn't connect to {0}, possible timeout or invalid hostname")

    # this is called when using this as a default destination plugin
    def upload(self, body, private_key, cert_chain, **kwargs):

        print("SFTP destination plugin is started")

        cn = self.host
        dst_path = self.certDestinationPath
        dst_path_cn = dst_path + "/" + cn
        export_format = self.exportFormat

        # prepare files for upload
        files = {cn + ".key": private_key, cn + ".pem": body}

        if cert_chain:
            if export_format == "NGINX":
                # assemble body + chain in the single file
                files[cn + ".pem"] += cert_chain

            elif export_format == "Apache":
                # store chain in the separate file
                files[cn + ".ca.bundle.pem"] = cert_chain

        self.upload_file(dst_path_cn, files)

    # this is called from the acme http challenge
    def upload_acme_token(self, token_path, token, dst_path=None, **kwargs):

        print("SFTP destination plugin is started for HTTP-01 challenge")

        dst_path = dst_path if dst_path else self.challengeDestinationPath
        dst_path = path.join(dst_path, token_path[1:])

        challPath, filename = path.split(dst_path)

        # prepare files for upload
        files = {filename: token}

        self.upload_file(challPath, files)

    # this is called from the acme http challenge
    def delete_acme_token(self, token_path, dst_path=None, **kwargs):

        dst_path = dst_path if dst_path else self.challengeDestinationPath
        dst_path = path.join(dst_path, token_path[1:])

        challPath, filename = path.split(dst_path)

        # prepare files for upload
        files = {filename: None}

        self.delete_file(challPath, files)

    # here the file is deleted
    def delete_file(self, dst_path, files):

        try:
            # open the ssh and sftp sessions
            sftp, ssh = self.open_sftp_connection()

            # delete files
            for filename, _ in files.items():
                print(
                    "Deleting {0} from {1}".format(filename, dst_path)
                )
                try:
                    sftp.remove(path.join(dst_path, filename))
                except PermissionError as permerror:
                    if permerror.errno == 13:
                        print(
                            "Deleting {0} from {1} returned Permission Denied Error, making file writable and retrying".format(
                                filename, dst_path)
                        )
                        sftp.chmod(path.join(dst_path, filename), 0o600)
                        sftp.remove(path.join(dst_path, filename))

            ssh.close()
        except (AuthenticationException, NoValidConnectionsError) as e:
            raise e
        except Exception as e:
            print("ERROR in {0}: {1}".format(e.__class__, e))
            try:
                ssh.close()
            except BaseException:
                pass

    # here the file is uploaded for real, this helps to keep this class DRY
    def upload_file(self, dst_path, files):

        try:
            # open the ssh and sftp sessions
            sftp, ssh = self.open_sftp_connection()

            # split the path into it's segments, so we can create it recursively
            allparts = []
            path_copy = dst_path
            while True:
                parts = path.split(path_copy)
                if parts[0] == path_copy:  # sentinel for absolute paths
                    allparts.insert(0, parts[0])
                    break
                elif parts[1] == path_copy:  # sentinel for relative paths
                    allparts.insert(0, parts[1])
                    break
                else:
                    path_copy = parts[0]
                    allparts.insert(0, parts[1])

            # make sure that the destination path exists, recursively
            remote_path = allparts[0]
            for part in allparts:
                try:
                    if part != "/" and part != "":
                        remote_path = path.join(remote_path, part)
                    sftp.stat(remote_path)
                except IOError:
                    print("{0} doesn't exist, trying to create it".format(
                        remote_path))
                    try:
                        sftp.mkdir(remote_path)
                    except IOError as ioerror:
                        print(
                            "Couldn't create {0}, error message: {1}".format(remote_path, ioerror))

            # upload certificate files to the sftp destination
            for filename, data in files.items():
                print(
                    "Uploading {0} to {1}".format(filename, dst_path)
                )
                try:
                    print("Debug 0")
                    with sftp.open(path.join(dst_path, filename), "w") as f:
                        print("Debug 1")
                        f.write(data)
                        print("Debug 2")
                except PermissionError as permerror:
                    if permerror.errno == 13:
                        print(
                            "Uploading {0} to {1} returned Permission Denied Error, making file writable and retrying".format(
                                filename, dst_path)
                        )
                        sftp.chmod(path.join(dst_path, filename), 0o600)
                        with sftp.open(path.join(dst_path, filename), "w") as f:
                            f.write(data)
                # most likely the upload user isn't the webuser, -rw-r--r--
                sftp.chmod(path.join(dst_path, filename), 0o644)

            ssh.close()

        except (AuthenticationException, NoValidConnectionsError) as e:
            raise e
        except Exception as e:
            print("ERROR in {0}: {1}".format(e.__class__, e))
            try:
                ssh.close()
            except BaseException:
                pass
            message = ''
            if hasattr(e, 'errors'):
                for _, error in e.errors.items():
                    message = error.strerror
                raise Exception(
                    'Couldn\'t upload file to {}, error message: {}'.format(self.host, message))
