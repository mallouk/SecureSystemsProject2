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
parser.add_argument('--client', action='store', required=True)
parser.add_argument('--check_in', action='store')
parser.add_argument('--check_out', action='store')
parser.add_argument('--sec_flag', action='store')
parser.add_argument('--delegate', action='store', nargs=5)
parser.add_argument('--safe_delete', action='store')

#Parse the args and place them in a var. We create the directory paths to wherever our certs and keys are for referencing.
args = parser.parse_args();

#Check if client actually exists
client_dir=os.getcwd()+ '/clients/' + args.client
if not os.path.isdir(client_dir):
    print("This client doesn't exist. Try again please.")
    exit()

#Presuming that our client does exist we will create all the certs for it. 
cert_auth_crt = os.getcwd() + '/ca/securesysCA.crt'
server_crt = os.getcwd() + '/server/securesysServer.crt'
client_crt = os.getcwd() + '/clients/' + args.client + '/securesysClient.crt'
client_key = os.getcwd() + '/clients/' + args.client + '/securesysClient.key'


#Bundle data together and determine what flags were passed to execute the respective code
if args.check_in != defaultArg:
    data={'client':args.client, 'file':args.check_in, 'sec_flag':args.sec_flag}
    r = requests.get("http://localhost:5000/check_in", verify = cert_auth_crt, params=data)
    print(r.text)

if args.check_out != defaultArg:
    data={'client':args.client, 'file':args.check_out}
    r = requests.get("http://localhost:5000/check_out", verify = cert_auth_crt, params=data)
    print r.text

if args.delegate != defaultArg:
    data={'client':args.client, 'delegate_file':args.delegate[0], 'delegate_client':args.delegate[1],
          'delegate_time':args.delegate[2], 'delegate_permission': args.delegate[3],
          'delegate_prop':args.delegate[4]}
    r = requests.get("http://localhost:5000/delegate", verify = cert_auth_crt, params=data)
    print('arg delegate')

if args.safe_delete != defaultArg:
    data={'client':args.client, 'file':args.safe_delete}
    r = requests.get("http://localhost:5000/safe_delete", verify = cert_auth_crt, params=data)
    print r.text


#r = requests.get("https://localhost/", verify = cert_auth_crt, params=data)

