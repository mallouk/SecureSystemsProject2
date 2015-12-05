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
clientDir = os.getcwd() + '/clients/' + args.client + '/files/'


#Bundle data together and determine what flags were passed to execute the respective code
if args.check_in != defaultArg:
    if not os.path.isfile(clientDir + args.check_in):
        print "File does not exist. Try again please."
        exit()
    curr_time_seconds = int(round(time.time()))
    data={'client':args.client, 'file':args.check_in, 'sec_flag':args.sec_flag, 'curr_time':curr_time_seconds}
    files={'files':open(clientDir + args.check_in, 'rb')}
    r = requests.post("https://localhost:5000/check_in", verify=cert_auth_crt, cert=(client_crt, client_key), params=data, files=files)
    print(r.text)

if args.check_out != defaultArg:
    curr_time_seconds = int(round(time.time()))
    data={'client':args.client, 'file':args.check_out, 'output':args.output,'curr_time':curr_time_seconds}
    r = requests.get("https://localhost:5000/check_out", verify = cert_auth_crt, params=data)
    if r.headers['ReadSuccess'] == 'true':
        fileTest = r.text
        writer = open(clientDir + args.output, 'w')
        writer.write(fileTest)
    print r.headers['DispMessage']

        
if args.delegate != defaultArg:
    curr_time_seconds = int(round(time.time()))
    data={'client':args.client, 'delegate_file':args.delegate[0], 'delegate_client':args.delegate[1],
          'delegate_time':args.delegate[2], 'delegate_permission': args.delegate[3],
          'delegate_prop':args.delegate[4], 'curr_time':curr_time_seconds}
    r = requests.get("https://localhost:5000/delegate", verify = cert_auth_crt, params=data)
    print(r.text)

if args.safe_delete != defaultArg:
    curr_time_seconds = int(round(time.time()))
    data={'client':args.client, 'file':args.safe_delete, 'curr_time': curr_time_seconds}
    r = requests.get("https://localhost:5000/safe_delete", verify = cert_auth_crt, params=data)
    print r.text


#r = requests.get("https://localhost/", verify = cert_auth_crt, params=data)

