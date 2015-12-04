import os
import sys
import requests
import argparse
import time

#Supress warnings when checking common name of CA cert
requests.packages.urllib3.disable_warnings()
defaultArg='NO_ARG_PASSED'
#Create parser object
parser = argparse.ArgumentParser(argument_default=defaultArg)

#Create parser arguments for checking, we store whatever value is passed to them.
parser.add_argument('--client', action='store', required=True)
parser.add_argument('--check_in', action='store')
parser.add_argument('--check_out', action='store')
parser.add_argument('--sec_flag', action='store')
parser.add_argument('--delegate', action='store', nargs=5)
parser.add_argument('--safe_delete', action='store')
parser.add_argument('--output', action='store')
parser.add_argument('--test', action='store')

args = parser.parse_args()

cert_auth_crt = os.getcwd() + '/ca/securesysCA.crt'
client_crt = os.getcwd() + '/clients/' + args.client + '/securesysClient.crt'
client_key = os.getcwd() + '/clients/' + args.client + '/securesysClient.key'

data={'enc_type':'multipart/form-data'}
#files={'file': open("/home/matthew/git/SecureSystemsProject2/test/"+args.test, 'rb')}



#r = requests.post("http://localhost:5000/test", verify=cert_auth_crt, cert=(client_crt, client_key), data=data, files=files)
data={'file':args.test}
r = requests.get("http://localhost:5000/down", verify=cert_auth_crt, cert=(client_crt, client_key), params=data)
print r.status_code
print r.headers
print r.text



