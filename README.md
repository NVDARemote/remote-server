# NVDA Remote Server Relay

This is a simple server used to relay connections for [NVDA Remote](https://nvdaremote.com)

## Basic Usage

- Install Python 3 and Pip
- Create a virtualenv
- Install requirements into virtualenv
- Obtain Certificate
- Run server.py inside virtualenv


## Docker

~~~
docker-compose up --build
~~~


This will expose the server on port 6837, the default.
You must create a folder called certificate along-side the docker-compose.yml which contains the certificate, private key, and root chain named as cert, key, and chain respectively.
