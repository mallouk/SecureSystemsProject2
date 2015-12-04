import os
import sys
import requests
import argparse
import time
from OpenSSL import SSL

#Supress warnings when checking common name of CA cert
requests.packages.urllib3.disable_warnings()
defaultArg='NO_ARG_PASSED'
#Create parser object
parser = argparse.ArgumentParser(argument_default=defaultArg)

#Create parser arguments for checking, we store whatever value is passed to them.
parser.add_argument('--client', action='store', required=True)

args = parser.parse_args()

cert_auth_crt = os.getcwd() + '/ca/securesysCA.crt'
client_crt = os.getcwd() + '/clients/' + args.client + '/securesysClient.crt'
client_key = os.getcwd() + '/clients/' + args.client + '/securesysClient.key'

r = requests.post("https://localhost:5000/test", verify=cert_auth_crt)

print r.status_code
print r.headers
print r.text



