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
import time

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

def can_delete(client, file_delete, serverDir, curr_time):
    with open(serverDir + '.' + file_delete, 'r') as metafile:
        first_line = metafile.readline()
        for line in metafile:
            if '***' in line:
                parse_del = line.split('***')
                if parse_del[0] == client or parse_del[0] == 'ALL':
                    if curr_time <= parse_del[1]:
                        if 'safedelete' in parse_del[2]:
                            return True
    return False
                    
def can_delegate(client, serverDir, file_delegate, permission, curr_time):
    with open(serverDir + '.' + file_delete, 'r') as metafile:
        first_line = metafile.readline()
        for line in metafile:
            if '***' in line:
                parse_del = line.split('***')
                if parse_del[0] == client or parse_del[0] == 'ALL':
                    if curr_time <= parse_del[1]:
                        if parse_del[3] == 'true':
                            if permission in parse_del[2] or permission == 'owner':
                                return True
    return False
    
def write_delegation(serverDir, file_delegate, client_delegate, expire_time, permission, prop_delegation):
    with open(serverDir + '.' + file_delegate, 'r') as metaFile:
        with open(serverDir + '.' + file_delegate + '_tmp', 'w') as metaFileWrite:
            first_line = metaFile.readline().replace('\n','')
            parsed_first_line = first_line.split('***')
            first_line=''
            
            for x in range(0, len(parsed_first_line)-1):
                first_line+=parsed_first_line[x]+'***'
                    
                first_line+='YES\n'
                metaFileWrite.write(first_line)
                for line in metaFile:
                    metaFileWrite.write(line)

                metaFileWrite.write('\n' + client_delegate + '***' + str(expire_time) + '***' + permission + '***' + prop_delegation)
                metaFileWrite.close()
                metaFile.close()
                os.remove(serverDir + '.' + file_delegate)
                os.rename(serverDir + '.' + file_delegate + '_tmp', serverDir + '.' + file_delegate)
            
#Check in method used 
@app.route("/check_in")
def check_in():
    #Pull in parameters from URL
    client = request.args.get('client')
    fileCheckIn = request.args.get('file')
    fileSecFlag = request.args.get('sec_flag')
    curr_time = request.args.get('curr_time')
    
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
    curr_time = request.args.get('curr_time')
    
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
    client = request.args.get('client')
    file_delete = request.args.get('file')
    curr_time = request.args.get('curr_time')
    serverDir = os.getcwd() + '/server/files/'
    clientDir = os.getcwd() + '/clients/' + client + '/files/'
    
    if not os.path.isfile(serverDir + file_delete):
        return "File doesn't exist. Try again please."
    else:
        #Check if we're the owner
        with open(serverDir + '.'+  file_delete, 'r') as metaFile:
            line = metaFile.readline().replace('\n','')
            parsedLine = line.replace('\n','').split('***')
            if parsedLine[len(parsedLine)-1] == 'NO' and not parsedLine[0] == client:
                return 'Sorry. You do not have permissions to access this file.'
            elif parsedLine[0] == client:
                os.remove(serverDir + file_delete)
                os.remove(serverDir + '.' + file_delete)
                return 'File deleted from server'
            else: #We check our delegations
                metaFile.close()
                canDel = can_delete(client, file_delete, serverDir, curr_time)
                if canDel:
                    os.remove(serverDir + file_delete)
                    os.remove(serverDir + '.' + file_delete)
                    return 'File deleted from server'
                else:
                    return 'Permission denied. You dont have access to delete this file.'

@app.route('/delegate')
def delegate():
    client = request.args.get('client')
    file_delegate = request.args.get('delegate_file')
    client_delegate = request.args.get('delegate_client')
    time_delegation = request.args.get('delegate_time')
    permission = request.args.get('delegate_permission')
    prop_delegation = request.args.get('delegate_prop')
    curr_time = request.args.get('curr_time')
    
    curr_time = int(float(curr_time))
    time_delegation = int(float(time_delegation))

    serverDir = os.getcwd() + '/server/files/'
    clientDir = os.getcwd() + '/clients/' + client + '/files/'
    clientDir_delegate = os.getcwd() + '/clients/' + client_delegate + '/files/'
    if not os.path.isfile(serverDir + file_delegate):
        return "File doesn't exist. Try again please."
    elif client == client_delegate:
        return "You can't delegate permissions to yourself as you're already an owner."
    elif time_delegation <= 0:
        return "You can't assign someone a delegation of negative or zero time."
    elif (not os.path.isdir(clientDir_delegate)) or clientDir_delegate == 'ALL':
        return "You must delegate to a client that currently exists."
    elif not (permission == 'checkin' or permission == 'checkout' or permission == 'checkin|checkout' or permission == 'owner' or permission == 'safedelete' or permission == 'safedelete|checkin' or permission == 'safedelete|checkout'):
        return "You must delegate either 'checkin', 'checkout', 'checkin|checkout' or 'owner' to a client. You've specificed some odd option. Try again please."
    elif prop_delegation != 'false' and prop_delegation != 'true':
        return "You must specific whether a particular client and delegation permissions via true/false."
    else: #Now we know we have all good data, so we insert our delegation into the system
        #First we check if the file is encrypted and decrypt it if it is.
        if '.enc' in file_delegate:
            #decrypt it and check if we own it
            isOwner = ''
            with open(serverDir + '.' + file_delegate, 'r') as meta:
                firstLine = meta.readline()
                isOwner = firstline[0]    
                expire_time = curr_time + time_delegation
                if isOwner == client:#We own it
                    write_delegation(serverDir, file_delegate, client_delegate, expire_time, permission, prop_delegation)
                    #RE-ENCRYPT HERE
                    return 'Metadata file decrypted, delegation written to file and file re-encrypted.'
                else: #We don't own it, check if we can delegate
                    canDelegate = can_delegate(client, serverDir, file_delegate permission, curr_time)
                    if canDelegate: #We can delegate!
                        write_delegation(serverDir, file_delegate, client_delegate, expire_time, permission, prop_delegation)
                        #RE-ENCRYPT HERE
                        return 'Metadata file decrypted, delegation written to file and file re-encrypted.'
                    else: #We cannot delegate.
                        return 'Permission denied, you cannot delegate.'
        else:#The file is not encrypted
            isOwner = ''
            with open(serverDir + '.' + file_delegate, 'r') as meta:
                firstLine = meta.readline()
                isOwner = firstline[0]    
                expire_time = curr_time + time_delegation
                if isOwner == client:#We own it
                    write_delegation(serverDir, file_delegate, client_delegate, expire_time, permission, prop_delegation)            
                    return 'Delegation written to file  .' + file_delegate
                else: #We don't own it, check if we can delegate
                    canDelegate = can_delegate(client, serverDir, file_delegate permission, curr_time)
                    if canDelegate: #We can delegate!
                        write_delegation(serverDir, file_delegate, client_delegate, expire_time, permission, prop_delegation)
                        return 'Delegation written to file  .' + file_delegate
                    else: #We cannot delegate.
                        return 'Permission denied, you cannot delegate.'

            
            
#Execute server and take requests
if __name__ == '__main__':
    app.run()
