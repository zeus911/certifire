import unittest
from unittest.mock import patch, Mock, MagicMock, mock_open

from flask import Flask
from paramiko.ssh_exception import AuthenticationException

from certifire import create_app
from certifire.plugins.destinations.models import Destination

class TestSftp(unittest.TestCase):
    def setUp(self):
        self.sftp_destination = Destination(1,'certifire.xyz')
        # Creates a new Flask application for a test duration. In python 3.8, manual push of application context is
        # needed to run tests in dev environment without getting error 'Working outside of application context'.
        _app = create_app(config_name="testing")
        self.ctx = _app.app_context()
        assert self.ctx
        self.ctx.push()

    def tearDown(self):
        self.ctx.pop()

    def test_failing_ssh_connection(self):
        sftp_destination = Destination(1, 'non-existent', 22, 'test_acme')
        dst_path = '/var/non-existent'
        files = {'first-file': 'data'}

        with self.assertRaises(AuthenticationException):
            sftp_destination.upload_file(dst_path, files)

    @patch("certifire.plugins.destinations.models.paramiko")
    def test_upload_file_single_with_password(self, mock_paramiko):
        sftp_destination = Destination(1, 'non-existent', 22, 'test_acme', 'test_password')
        dst_path = '/var/non-existent'
        files = {'first-file': 'data'}

        mock_sftp = Mock()
        mock_sftp.open = mock_open()

        mock_ssh = mock_paramiko.SSHClient.return_value
        mock_ssh.connect = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp

        sftp_destination.upload_file(dst_path, files)

        mock_sftp.open.assert_called_once_with('/var/non-existent/first-file', 'w')
        handle = mock_sftp.open()
        handle.write.assert_called_once_with('data')
        mock_ssh.close.assert_called_once()
        mock_ssh.connect.assert_called_with('non-existent', username='test_acme', port=22,
                                            password='test_password')

    @patch("certifire.plugins.destinations.models.paramiko")
    def test_upload_file_multiple_with_key(self, mock_paramiko):
        sftp_destination = Destination(1, 'non-existent', 22, 'test_acme', None, 'ssh-rsa test-key', 'ssh-key-password')
        dst_path = '/var/non-existent'
        files = {'first-file': 'data', 'second-file': 'data2'}

        mock_sftp = Mock()
        mock_sftp.open = mock_open()

        mock_paramiko.RSAKey.from_private_key_file.return_value = 'ssh-rsa test-key'

        mock_ssh = mock_paramiko.SSHClient.return_value
        mock_ssh.connect = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp

        sftp_destination.upload_file(dst_path, files)

        mock_sftp.open.assert_called_with('/var/non-existent/second-file', 'w')
        handle = mock_sftp.open()
        handle.write.assert_called_with('data2')
        mock_ssh.close.assert_called_once()

        mock_paramiko.RSAKey.from_private_key_file.assert_called_with('ssh-rsa test-key', 'ssh-key-password')
        mock_ssh.connect.assert_called_with('non-existent', username='test_acme', port=22,
                                            pkey='ssh-rsa test-key')

    @patch("certifire.plugins.destinations.models.paramiko")
    def test_upload_acme_token(self, mock_paramiko):
        sftp_destination = Destination(1, 'non-existent', 22, 'test_acme', 'test_password', challengeDestinationPath='/var/destination-path')
        token_path = './well-known/acme-challenge/some-token-path'
        token = 'token-data'

        mock_sftp = Mock()
        mock_sftp.open = mock_open()

        mock_ssh = mock_paramiko.SSHClient.return_value
        mock_ssh.connect = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp

        sftp_destination.upload_acme_token(token_path, token)

        mock_sftp.open.assert_called_once_with('/well-known/acme-challenge/some-token-path', 'w')
        handle = mock_sftp.open()
        handle.write.assert_called_once_with('token-data')
        mock_ssh.close.assert_called_once()
        mock_ssh.connect.assert_called_with('non-existent', username='test_acme', port=22,
                                            password='test_password')


    @patch("certifire.plugins.destinations.models.paramiko")
    def test_delete_file_with_password(self, mock_paramiko):
        sftp_destination = Destination(1, 'non-existent', 22, 'test_acme', 'test_password')
        dst_path = '/var/non-existent'
        files = {'first-file': None}

        mock_sftp = Mock()

        mock_ssh = mock_paramiko.SSHClient.return_value
        mock_ssh.connect = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp

        sftp_destination.delete_file(dst_path, files)

        mock_sftp.remove.assert_called_once_with('/var/non-existent/first-file')
        mock_ssh.close.assert_called_once()
        mock_ssh.connect.assert_called_with('non-existent', username='test_acme', port=22,
                                            password='test_password')

    @patch("certifire.plugins.destinations.models.paramiko")
    def test_delete_acme_token(self, mock_paramiko):
        sftp_destination = Destination(1, 'non-existent', 22, 'test_acme', 'test_password', challengeDestinationPath='/var/destination-path')
        token_path = './well-known/acme-challenge/some-token-path'

        mock_sftp = Mock()

        mock_ssh = mock_paramiko.SSHClient.return_value
        mock_ssh.connect = MagicMock()
        mock_ssh.open_sftp.return_value = mock_sftp

        sftp_destination.delete_acme_token(token_path)

        mock_sftp.remove.assert_called_once_with('/well-known/acme-challenge/some-token-path')
        mock_ssh.close.assert_called_once()
        mock_ssh.connect.assert_called_with('non-existent', username='test_acme', port=22,
                                            password='test_password')
