import requests
import os
import sys
import argparse

requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser()
parser.add_argument('--debug', dest='debug', action='store_true')
parser.add_argument('--check_out', dest='check_out', action='store', nargs=2, metavar=("FileName", "SaveLocation"))
parser.add_argument('--check_in', dest='check_in', action='store', nargs=3, metavar=("FileName", "SecurityFlag", "NameToServer"))
parser.add_argument('--delegate', dest='delegate', action='store', nargs=5, metavar=("FileName", "ClientName", "Time", "Permission", "Propagation"))
parser.add_argument('--safe_delete', dest='safe_delete', action='store', nargs=1,  metavar=("Filename"))
parser.add_argument('--name', dest='name', action='store', required=True)

args = parser.parse_args()

capath = os.path.split(os.getcwd())[0] + '/ca/certs/ca.cert.pem'
clientcertpath = os.path.split(os.getcwd())[0] + '/client_cert_' + args.name 
+ "/client.crt.pem"
clientkeypath = os.path.split(os.getcwd())[0] + '/client_cert_' + args.name 
+ "/client.key.pem"

def get(uri, params):
   r = None

   if args.debug:
       r = requests.get('http://murderface.gtisc.gatech.edu:5000/s2dr' + uri, params=params)
   else:
       r = requests.get('https://murderface.gtisc.gatech.edu/s2dr' + uri, verify=capath, cert=(clientcertpath, clientkeypath), params=params)

   return r

def postfile(uri, data, files):
   r = None

   if args.debug:
       r = requests.post('http://murderface.gtisc.gatech.edu:5000/s2dr' + uri, data=data, files=files)
   else:
       r = requests.post('https://murderface.gtisc.gatech.edu/s2dr' + uri, verify=capath, cert=(clientcertpath, clientkeypath), data=data, files=files)

   return r

def checkin(args, name):
   data = {'sflag': args[1], 'name': name, 'filename':args[2]}

   files = {'file': open(args[0], 'rb')}

   r = postfile('/checkin', data, files)

   print r.text

def checkout(args, name):
   payload = {'name': name, 'file': args[0]}

   r = get('/checkout', payload)

   f = open(args[1], 'w')
   f.write(r.text)
   f.close()
   print r.text
   
def delegate(args, name):
   payload = {'name' : name, 'file': args[0], "clientToShare" : args[1], 'permission' : args[3], 'pflag': args[4], 'time':args[2] }

   r = get('/delegate', payload)

   print r.text

def safe_delete(args, name):
   payload = {'name' : name, 'file':args[0]}

   r = get('/safe_delete', payload)

   print r.text

if args.check_in != None:
   checkin(args.check_in, args.name 
)
if args.check_out != None:
   checkout(args.check_out, args.name 
)
if args.delegate != None:
   delegate(args.delegate, args.name 
)
if args.safe_delete != None:
   safe_delete(args.safe_delete, args.name 
)