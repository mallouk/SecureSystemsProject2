import os
import sys
import requests
import argparse

#Supress warnings when checking common name of CA cert
requests.packages.urllib3.disable_warnings()
defaultArg='NO_ARG_PASSED'
#Create parser object
parser = argparse.ArgumentParser(argument_default=defaultArg)

#Create parser arguments for checking, we store whatever value is passed to them.
parser.add_argument('--check_in', action='store', nargs=2)
parser.add_argument('--check_out', action='store')
parser.add_argument('--delegate', action='store')
parser.add_argument('--client', action='store', required=True)

#Parse the args and place them in a var. We create the directory paths to wherever our certs and keys are for referencing.
args = parser.parse_args();
cert_auth_crt = os.getcwd() + '/ca/securesysCA.crt'
server_crt = os.getcwd() + '/server/securesysServer.crt'
client_crt = os.getcwd() + '/clients/' + args.client + '/securesysClient.crt'
client_key = os.getcwd() + '/clients/' + args.client + '/securesysClient.key'

if args.check_in != defaultArg:
    r = requests.get("http://localhost:5000/check_in", verify = cert_auth_crt, params=data)
elif args.check_out != defaultArg:
    print('arg checkout')
elif args.delegate != defaultArg:
    pring('arg delegate')
    

data={'client':args.client,'check_in':args.check_in}
#r = requests.get("https://localhost/", verify = cert_auth_crt, params=data)

print(r.text)

