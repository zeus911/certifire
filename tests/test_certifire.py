import base64
import json
import os
import unittest

from certifire import create_app, database, db, plugins, users


class CertifireTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app(config_name="testing")
        self.client = self.app.test_client

        with self.app.app_context():
            db.create_all()
            user = users.User('admin', 'admin', True)
            database.add(user)
    
    def tearDown(self):
        with self.app.app_context():
            db.drop_all()
    
    def register_user(self, username="testuser", password="test1234"):
        creds = base64.b64encode(b'admin:admin').decode('utf-8')
        user_data = {
            'username': username,
            'password': password
        }
        return self.client().post('/api/users', json=user_data, headers={'Authorization': 'Basic ' + creds})
    
    def test_init(self):
        res = self.client().get('/')
        self.assertEqual(res.status_code, 200)

    def test_user(self):
        res = self.client().get('/api/public')
        self.assertEqual(res.status_code, 200)
    
    def test_basic_auth_prompt(self):
        response = self.client().get('/api/resource')
        self.assertEqual(response.status_code, 401)
        self.assertTrue('WWW-Authenticate' in response.headers)
        self.assertEqual(response.headers['WWW-Authenticate'],
                         'Basic realm="Authentication Required"')
    
    def test_basic_auth_ignore_options(self):
        response = self.client().options('/api/resource')
        self.assertEqual(response.status_code, 200)
        self.assertTrue('WWW-Authenticate' not in response.headers)
    
    def test_basic_auth_login_valid(self):
        creds = base64.b64encode(b'admin:admin').decode('utf-8')
        response = self.client().get(
            '/api/resource', headers={'Authorization': 'Basic ' + creds})
        self.assertDictEqual(response.json, {'data': 'Hello, admin!'})
    
    def test_user_registration(self):
        res = self.register_user()
        self.assertEqual(res.status_code, 201)

        creds = base64.b64encode(b'testuser:test1234').decode('utf-8')
        response = self.client().get(
            '/api/resource', headers={'Authorization': 'Basic ' + creds})
        self.assertDictEqual(response.json, {'data': 'Hello, testuser!'})
    
    def test_token_authentication(self):
        creds = base64.b64encode(b'admin:admin').decode('utf-8')
        response = self.client().get(
            '/api/token', headers={'Authorization': 'Basic ' + creds})

        token = response.json['token']
        token = token+':x'
        creds = base64.b64encode(token.encode()).decode('utf-8')
        response = self.client().get(
            '/api/resource', headers={'Authorization': 'Basic ' + creds})
        self.assertDictEqual(response.json, {'data': 'Hello, admin!'})


if __name__ == "__main__":
    unittest.main()
