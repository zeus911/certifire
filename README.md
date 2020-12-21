Certifire-Minimal
=========

Installation
------------

Create and switch to new user
    
    $ sudo useradd -m -s /bin/bash -G sudo -c "Certifire API Server" certifire
    $ sudo passwd certifire
    $ sudo su - certifire


Install dependencies

    $ sudo apt update && sudo apt upgrade
    $ sudo apt install python3-dev python3-pip python3-virtualenv libpq-dev build-essential libssl-dev libffi-dev nginx git postgresql awscli certbot python3-certbot-nginx
    $ sudo systemctl enable --now postgresql.service

Setup Postgresql

    $ sudo su - postgres
    $ psql

    postgres# CREATE USER certifire WITH PASSWORD 'certifire';
    postgres# ALTER USER certifire WITH SUPERUSER;
    postgres# CREATE DATABASE certifire;
    postgres# exit

    $ exit

After cloning, create a virtual environment and install the requirements. For Linux and Mac users:

    $ git clone https://github.com/certi-fire/certifire -b minimal
    $ virtualenv -p python3 certifire
    $ source certifire/bin/activate
    $ cd certifire
    (certifire) $ pip install -r requirements.txt
    (certifire) $ python setup.py install

Edit nginx configration for proxy

    $ sudo nano /etc/nginx/sites-available/default

Edit the config to look like this (change server_name accordingly):

    server {
        listen 80 default_server;
        listen [::]:80 default_server;

        root /var/www/html;
        index index.html index.htm index.nginx-debian.html;

        server_name api.certifire.xyz;

        location / {
                try_files $uri $uri/ =404;
        }

        location /api {
                proxy_pass  http://127.0.0.1:5000;
                proxy_next_upstream error timeout invalid_header http_500 http_502 http_503 http_504;
                proxy_redirect off;
                proxy_buffering off;
                proxy_set_header        Host            $host;
                proxy_set_header        X-Real-IP       $remote_addr;
                proxy_set_header        X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    }

Then restart nginx

    $ sudo systemctl restart nginx.service 

(optional) Run certbot for https - Instructions for ubuntu 20.04 server given

    $ sudo certbot --nginx

Configure aws credentials for route53 dns:

    $ aws configure
    
Running
-------

In postgresql, setup a database and make appropriate changes to config.py
To run the server use the following command:

    (certifire) $ certifire-manager init
    (certifire) $ certifire-manager runserver
     * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
     * Restarting with reloader

Now the server is ready to accept requests at https://api.certifire.xyz (or whatever you have configured)

To run certifire as a service:

    $ sudo cp certifire.service /etc/systemd/system/
    $ sudo systemctl daemon-reload
    $ sudo systemctl enable --now certifire

API Documentation
-----------------

- POST **/api/users**

    Register a new user.<br>
    The body must contain a JSON object that defines `username` and `password` fields.<br>
    On success a status code 201 is returned. The body of the response contains a JSON object with the newly added user. A `Location` header contains the URI of the new user.<br>
    On failure status code 400 (bad request) is returned.<br>
    Notes:
    - The password is hashed before it is stored in the database. Once hashed, the original password is discarded.
    - In a production deployment secure HTTP must be used to protect the password in transit.

- GET **/api/users/&lt;int:id&gt;**

    Return a user.<br>
    On success a status code 200 is returned. The body of the response contains a JSON object with the requested user.<br>
    On failure status code 400 (bad request) is returned.

- GET **/api/token**

    Return an authentication token.<br>
    This request must be authenticated using a HTTP Basic Authentication header.<br>
    On success a JSON object is returned with a field `token` set to the authentication token for the user and a field `duration` set to the (approximate) number of seconds the token is valid.<br>
    On failure status code 401 (unauthorized) is returned.

- GET **/api/resource**

    Return a protected resource.<br>
    This request must be authenticated using a HTTP Basic Authentication header. Instead of username and password, the client can provide a valid authentication token in the username field. If using an authentication token the password field is not used and can be set to any value.<br>
    On success a JSON object with data for the authenticated user is returned.<br>
    On failure status code 401 (unauthorized) is returned.

Example
-------

The following `curl` command registers a new user with username `miguel` and password `python`:

    $ curl -i -X POST -H "Content-Type: application/json" -d '{"username":"hawk","password":"changeme"}' http://127.0.0.1:5000/api/users
    HTTP/1.0 201 CREATED
    Content-Type: application/json
    Content-Length: 27
    Location: http://127.0.0.1:5000/api/users/1
    Server: Werkzeug/0.9.4 Python/2.7.3
    Date: Thu, 28 Nov 2013 19:56:39 GMT
    
    {
      "username": "hawk"
    }

These credentials can now be used to access protected resources:

    $ curl -u hawk:chngeme -i -X GET http://127.0.0.1:5000/api/resource
    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 30
    Server: Werkzeug/0.9.4 Python/2.7.3
    Date: Thu, 28 Nov 2013 20:02:25 GMT
    
    {
      "data": "Hello, hawk!"
    }

Using the wrong credentials the request is refused:

    $ curl -u hawk:loremipsum -i -X GET http://127.0.0.1:5000/api/resource
    HTTP/1.0 401 UNAUTHORIZED
    Content-Type: text/html; charset=utf-8
    Content-Length: 19
    WWW-Authenticate: Basic realm="Authentication Required"
    Server: Werkzeug/0.9.4 Python/2.7.3
    Date: Thu, 28 Nov 2013 20:03:18 GMT
    
    Unauthorized Access

Finally, to avoid sending username and password with every request an authentication token can be requested:

    $ curl -u hawk:changeme -i -X GET http://127.0.0.1:5000/api/token
    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 139
    Server: Werkzeug/0.9.4 Python/2.7.3
    Date: Thu, 28 Nov 2013 20:04:15 GMT
    
    {
      "duration": 600,
      "token": "eyJhbGciOiJIUzI1NiIsImV4cCI6MTM4NTY2OTY1NSwiaWF0IjoxMzg1NjY5MDU1fQ.eyJpZCI6MX0.XbOEFJkhjHJ5uRINh2JA1BPzXjSohKYDRT472wGOvjc"
    }

And now during the token validity period there is no need to send username and password to authenticate anymore:

    $ curl -u eyJhbGciOiJIUzI1NiIsImV4cCI6MTM4NTY2OTY1NSwiaWF0IjoxMzg1NjY5MDU1fQ.eyJpZCI6MX0.XbOEFJkhjHJ5uRINh2JA1BPzXjSohKYDRT472wGOvjc:x -i -X GET http://127.0.0.1:5000/api/resource
    HTTP/1.0 200 OK
    Content-Type: application/json
    Content-Length: 30
    Server: Werkzeug/0.9.4 Python/2.7.3
    Date: Thu, 28 Nov 2013 20:05:08 GMT
    
    {
      "data": "Hello, hawk!"
    }

Once the token expires it cannot be used anymore and the client needs to request a new one. Note that in this last example the password is arbitrarily set to `x`, since the password isn't used for token authentication.

An interesting side effect of this implementation is that it is possible to use an unexpired token as authentication to request a new token that extends the expiration time. This effectively allows the client to change from one token to the next and never need to send username and password after the initial token was obtained.

