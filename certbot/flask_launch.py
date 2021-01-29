#!/usr/bin/env python3
from flask import Flask,request
import http.client as http_client
import logging

from app import lambda_handler

app=Flask(__name__)
http_client.HTTPConnection.debuglevel = 1
logging.basicConfig()
logging.getLogger().setLevel(logging.DEBUG)
requests_log = logging.getLogger("requests.packages.urllib3")
requests_log.setLevel(logging.DEBUG)
requests_log.propagate = True

@app.route('/certbot',methods=['POST'])
def certbot():
	print(request.data.decode())
	print(dict(request.headers))
	print(lambda_handler({"headers":dict(request.headers),"body":request.data.decode()},None))
	return('OK')

if __name__=="__main__":
	app.run(debug=True)