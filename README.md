# certbot

This is the source code for @certbot webex bot to provide some utilities for certificate handling.
It's writted to work as an AWS Lambda function, but can work with any other framework like flask

flask_launch.py will run a local webserver to quickly test the code on the local workstation. launch.json file contains a VS Code debug option to run the code through flask.

setdevhook.py is a quick script to launch localtunnel (lt) utility and update webex webhook to point to the local flask web server

template-nokeys.yaml file needs to be renamed to template.yaml. The environment variable section needs to be populated with the proper API keys

Lambda function can be build using sam build --debug --use-container --cached command and deployed using sam deploy