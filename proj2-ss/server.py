from flask import Flask
from flask import Flask, request
from Crypto.Cipher import AES
import os
import sys
import requests
import shutil
import string
import random
import struct
app = Flask(__name__)

#Method to encrypt a file. Give it a key and file to encrypt. It will spit back out an encrypted version of said file. 
def encrypt_file(key, in_filename):
    out_filename = ''
    chunksize=64*1024
    if not out_filename:
        out_filename = in_filename + '.enc'

    #Generate IV, get file size, and encrypting object for AES
    iv = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
    encryptor = AES.new(key, AES.MODE_CBC, iv)
    filesize = os.path.getsize(in_filename)

    #Write file to disk
    with open(in_filename, 'rb') as infile:
        with open(out_filename, 'wb') as outfile:
            outfile.write(struct.pack('<Q', filesize))
            outfile.write(iv)

            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += ' ' * (16 - len(chunk) % 16)

                outfile.write(encryptor.encrypt(chunk))

#Method to decrypt file, given a key, ciphertext file, and the name of what the file should be called, this method should return a decrypted version of a file.
def decrypt_file(key, in_filename, out_filename=None):
    chunksize = 24*1024
    if not out_filename:
        out_filename = os.path.splitext(in_filename)[0]

    #Generate IV, and decryptor object.
    with open(in_filename, 'rb') as infile:
        origsize = struct.unpack('<Q', infile.read(struct.calcsize('Q')))[0]
        iv = infile.read(16)
        decryptor = AES.new(key, AES.MODE_CBC, iv)

        #Write file to disk
        with open(out_filename, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)
                if len(chunk) == 0:
                    break
                outfile.write(decryptor.decrypt(chunk))

            outfile.truncate(origsize)

#Check in method used 
@app.route("/check_in")
def check_in():
    #Pull in parameters from URL
    client = request.args.get('client')
    fileCheckIn = request.args.get('file')
    fileSecFlag = request.args.get('sec_flag')

    #Sanitize and get absolute dirs for files
    fullPathFile = os.getcwd()+ '/clients/' + client + '/files/' + fileCheckIn
    serverDir = os.getcwd() + '/server/files/'

    #If file exists, check the sec flag and transfer file accordiingly. Otherwise, throw an error saying that the file doesn't exist
    if not os.path.isfile(fullPathFile):
        return "File doesn't exist. Try again please."
    else:
        #Deal with specific flag options
        if fileSecFlag == 'CONFIDENTIALITY':
            #Generate random key used for encryption
            randomKey = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(32))
            #Write owner and  key to a metadata file.....
            filePointer = open(serverDir + '.' + fileCheckIn + '.enc', 'w')
            delegationFlag = 'NO'
            dataToFile = client + '***' + randomKey + '***' + delegationFlag
            filePointer.write(dataToFile)
            filePointer.close()
            
            #Encrypt file and send it to server
            encrypt_file(randomKey, fullPathFile + '')
            if os.path.isfile(serverDir + fileCheckIn + '.enc'):
                os.remove(serverDir + fileCheckIn + '.enc')
            shutil.move(fullPathFile + '.enc', serverDir)
            return 'File encrypted and sent to server.'
        elif fileSecFlag == 'INTEGRITY':
            print 'int'
            return 'File signed and sent to server.'
            #Doc Sign
        else:
            #Write metadata file
            filePointer = open(serverDir + '.' + fileCheckIn, 'w')
            delegationFlag = 'NO'
            dataToFile = client + '***' + delegationFlag
            filePointer.write(dataToFile)
            filePointer.close()
            
            #Send actual file to server
            shutil.copy(fullPathFile, serverDir)
            return 'File sent to server, but because your flag does not match either CONFIDENTIALITY or INTEGRITY, a flag of NONE has been presumed.'

#Checkout method
@app.route("/check_out")
def checkout():
    return 'check_out'

#Execute server and take requests
if __name__ == '__main__':
    app.run()
