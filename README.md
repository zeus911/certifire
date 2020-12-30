Certifire
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

### Note

If you are hosting in an AWS EC2 instance, please make sure to edit the security groups,
Network Access Control Lists to allow traffic for ports 80 and 443 and other shenanigans.

More Info: [AWS Knowledge Center](https://aws.amazon.com/premiumsupport/knowledge-center/connect-http-https-ec2/)

There are similar quirks if hosted in GCP. These works out of the box for hosting services like
DigitalOcean, Linode etc...

Then in the system, if you are using a firewall (defaultly enabled in rhel based systems), 
you may need to open ports 80 and 433 


Running
-------

In postgresql, setup a database and make appropriate changes to config.py
Change the password of admin account as required in the init commnd.
To run the server use the following commands:

    (certifire) $ certifire-manager init -p changeme
    (certifire) $ certifire-manager runserver
     * Running on http://127.0.0.1:5000/ (Press CTRL+C to quit)
     * Restarting with reloader

Now the server is ready to accept requests at https://api.certifire.xyz (or whatever you have configured)

To run certifire as a service:

    $ sudo cp certifire.service /etc/systemd/system/
    $ sudo systemctl daemon-reload
    $ sudo systemctl enable --now certifire

Upgrading
---------

Databse migrations not implemented yet. You will have to drop the database and recreate
for mid to high version chenges (eg. v0.1.0 to v0.2.0)

!! Doing this will delete all your accounts and certificates, proceed with care !!

    (certifire) $ certifire-manager drop_db
    (certifire) $ git pull
    (certifire) $ pip install -r requirements.txt
    (certifire) $ python setup.py install
    (certifire) $ certifire-manager init
    (certifire) $ certifire-manager runserver

API Documentation
-----------------

[API Documentation](./README_API.md)

CLI Documentation
-----------------

Get interactive help from the CLI itself, run:

    $ certifire --help
    $ certifire register --help
    $ certifire issue --help
    $ certifire revoke --help

To get current version of certifire:

    $ certifire version
