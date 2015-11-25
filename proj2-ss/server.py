from flask import Flask
from flask import Flask, request
import os
import sys
import requests
app = Flask(__name__)

@app.route("/check_in")
def check_in():
    check_in = request.args.get('check_in')
    client = request.args.get('client')    
    return client+''

@app.route("/check_out")
def checkout():
    return 'check_out'

if __name__ == '__main__':
    app.run()
