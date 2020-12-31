Certifire
=========

Installation
------------

Install dependencies: 

(Debian/Ubuntu and derivatives)

    $ sudo apt update && sudo apt upgrade
    $ sudo apt install git nginx awscli certbot python3-certbot-nginx

(RHEL, CentOS, Fedora)

    $ sudo dnf upgrade
    $ sudo dnf install git nginx awscli certbot python3-certbot-nginx

Configure aws credentials for route53 dns:

    $ aws configure

### Select one of the following methods

<details>
<summary>Legacy Installation (Tested on Ubuntu 20.04)</summary>

### Legacy Installation

Create and switch to new user
    
    $ sudo useradd -m -s /bin/bash -G sudo -c "Certifire API Server" certifire
    $ sudo passwd certifire
    $ sudo su - certifire

Install dependencies

    $ sudo apt install python3-dev python3-pip python3-virtualenv libpq-dev build-essential libssl-dev libffi-dev postgresql
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

Make appropriate changes to [config.py](./certifire/config.py)

    (certifire) $ python setup.py install

Running

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

</details>

<details>
<summary>Docker Installation (Tested on Ubuntu 20.04)</summary>

### Docker Installation

Install docker and docker-compose

    $ sudo apt install docker docker-compose
    $ sudo groupadd docker
    $ sudo usermod -aG docker certifire

Log out and Log back in so that your group membership is re-evaluated. 
More info: [Docker Docs](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user)

You also may stop existing postgresql instance and certifire instance if present because,
it will confilict with the postgres and certifire docker instance

    $ sudo systemctl disable --now postgresql
    $ sudo systemctl disable --now certifire

Now we build our docker image

    $ git clone https://github.com/certifire/certifire
    $ cd certifire
    $ docker-compose build

Run the container:

    $ docker-compose up -d

Initialize database and admin accounts (change the password as you require):

    $ docker-compose exec server certifire-manager init -p changeme

If you want to stream the logs (You can press ctrl+c to quit streaming):

    $ docker-compose logs -tf server

</details>

<details>
<summary>Podman Installation !Experimental! (Tested on CentOS 8 and Fedora 33)</summary>

### Podman Installation

Install podman and podman-compose

    $ sudo dnf install podman podman-compose

Log out and Log back in so that your group membership is re-evaluated. 
More info: [Docker Docs](https://docs.docker.com/engine/install/linux-postinstall/#manage-docker-as-a-non-root-user)

You also may stop existing postgresql instance and certifire instance if present because,
it will confilict with the postgres and certifire docker instance

    $ sudo systemctl disable --now postgresql
    $ sudo systemctl disable --now certifire

Now we build our docker image

    $ git clone https://github.com/certifire/certifire
    $ cd certifire
    $ podman-compose build

Run the container:

    $ podman-compose up -d

Initialize database and admin accounts (change the password as you require):

    $ podman exec -it certifire_server_1 certifire-manager init changeme

If you want to stream the logs (You can press ctrl+c to quit streaming):

    $ podman-compose logs -tf server

</details>
<br>

Edit nginx configration for proxy 
(Ubuntu based conf shown, change nginx conf path appropriately for rhel based systems)

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

(optional) Run certbot for https

    $ sudo certbot --nginx

### Note

If you are hosting in an AWS EC2 instance, please make sure to edit the security groups,
Network Access Control Lists to allow traffic for ports 80 and 443 and other shenanigans.

More Info: [AWS Knowledge Center](https://aws.amazon.com/premiumsupport/knowledge-center/connect-http-https-ec2/)

There are similar quirks if hosted in GCP, ORACLE cloud etc.. 
These works out of the box for hosting services like DigitalOcean, Linode etc...

Then in the system, if you are using a firewall (defaultly enabled in rhel based systems), 
you may need to open ports 80 and 433 


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
