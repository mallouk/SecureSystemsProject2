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
import hashlib
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
            #Write file to server
            shutil.copyfile(fullPathFile, serverDir + fileCheckIn + '.sign')
            #Get file contents
            message = ''
            with open(serverDir + fileCheckIn + '.sign') as myfile:
                message = myfile.read().replace('\n', '')

            #Generate signature and construct metadata file
            hash_sha2 = hashlib.sha256(message).hexdigest()
            filePointer = open(serverDir + '.' + fileCheckIn + '.sign', 'w')
            delegationFlag = 'NO'
            dataToFile = client + '***' + hash_sha2 + '***' + delegationFlag
            filePointer.write(dataToFile)
            filePointer.close()
            return 'File signed and sent to server.'
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
def check_out():
    client = request.args.get('client')
    fileCheckIn = request.args.get('file')
    serverDir = os.getcwd() + '/server/files/'
    clientDir = os.getcwd() + '/clients/' + client + '/files/'
    if not os.path.isfile(serverDir + fileCheckIn):
        return "File doesn't exist. Try again please."
    else:
        #Check if we're the owner
        line_counter = 1
        with open(serverDir + '.'+  fileCheckIn, 'r') as metaFile:
            for line in metaFile:
                if line_counter == 1:
                    parsedLine = line.replace('\n','').split('***')
                    if parsedLine[len(parsedLine)-1] == 'NO' and not parsedLine[0] == client:
                        return 'Sorry. You do not have permissions to access this file.'
                    elif parsedLine[0] == client:
                        #We check to see if we're scanning a NONE sec_flag metadata file, and if we are, we just send the data back. Otherwise, we may have to check hashes or decrypt the file.
                        if len(parsedLine) == 2:
                            shutil.copy(serverDir + fileCheckIn, clientDir)
                            return 'File copied from server to client: ' + client
                        else:
                            fileExten=fileCheckIn.split('.')
                            key_or_hash = parsedLine[1]
                            #If file is .enc then we need to decrypt, else check signature
                            if fileExten[1] == 'enc':
                                decrypt_file(key_or_hash, serverDir + fileCheckIn, clientDir + fileExten[0])
                                return 'File decrypted and sent back to the client: ' + client
                            #Since our file isn't enc it is sign and therefore under the INTEGRITY flag.
                            else:
                                message = ''
                                with open(serverDir + fileCheckIn) as myfile:
                                    message = myfile.read().replace('\n', '')

                                hash_sha2 = hashlib.sha256(message).hexdigest()
                                if (hash_sha2 == parsedLine[1]):
                                    shutil.copyfile(serverDir + fileCheckIn, clientDir + fileExten[0])
                                    return 'File signatured checked and match confirmed. File sent to client: ' + client
                                else:
                                    return 'File signatured checked with no match. File transfered aborted.'
                    else: #If we have a delegation flag of 'YES' and we aren't the owner, execute this.
                        return 'Will handle delegation'
    return 'check_out'

@app.route('/safe_delete')
def safe_delete():
    return 'safe'
    

#Execute server and take requests
if __name__ == '__main__':
    app.run()
