import os
import sys
import requests
import argparse

#Supress warnings when checking common name of CA cert
requests.packages.urllib3.disable_warnings()

#Create parser object
parser = argparse.ArgumentParser()

#Create parser arguments for checking, we store whatever value is passed to them.
parser.add_argument('--check_in', action='store')
parser.add_argument('--client', action='store')

#Parse the args and place them in a var. We create the directory paths to wherever our certs and keys are for referencing.
args = parser.parse_args();
cert_auth_crt = os.getcwd() + '/ca/securesysCA.crt'
server_crt = os.getcwd() + '/server/securesysServer.crt'
client_crt = os.getcwd() + '/clients/' + args.client + '/securesysClient.crt'
client_key = os.getcwd() + '/clients/' + args.client + '/securesysClient.key'

data={'client':args.client,'check_in':args.check_in}
r = requests.get("https://localhost/", verify = cert_auth_crt, params=data)
print(r.text)
