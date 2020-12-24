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

    $ git clone https://github.com/certifire/certifire
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

[API Documentation](./README_API.md)