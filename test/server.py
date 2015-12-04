from flask import Flask
from flask import Flask, request, redirect, url_for
from flask import send_from_directory
from werkzeug import secure_filename
from functools import wraps
import os, sys, requests, string, random, struct
from OpenSSL import SSL
import ssl
#context = SSL.Context(SSL.SSLv23_METHOD)
#context.use_privatekey_file('server/securesysServer.key')
#context.use_certificate_file('server/securesysServer.crt')
#context = ssl.
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.load_cert_chain('server/securesysServer.crt', 'server/securesysServer.key')
UPLOAD_FOLDER = 'joe'


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/test', methods=['POST'])
def test():
    return 'okay'

    


if __name__ == '__main__':
    #app.run()
    app.run(host='127.0.0.1',debug=True,ssl_context=context)
