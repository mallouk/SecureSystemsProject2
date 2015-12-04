import os
import sys
import hashlib

def verify_signature(serverDir, fileCheckIn, origin_hash):
    message = ''
    with open(serverDir + fileCheckIn) as myfile:
        message = myfile.read().replace('\n', '')
        
        hash_sha2 = hashlib.sha256(message).hexdigest()
        if (hash_sha2 == origin_hash):
            return True
        else:
            return False


first_line=''
serverDir = '/home/matthew/git/SecureSystemsProject2/proj2-ss/server/files/'
if not os.path.isfile(serverDir + sys.argv[1]):
    print "File doesn't exist, try again please."
else:
    if os.path.isfile(serverDir + '.' + sys.argv[1] + '.sign'):
        with open(serverDir + '.' + sys.argv[1] + '.sign', 'r') as metafile:
            first_line = metafile.readline().replace('\n','')
            parsed = first_line.split('***')
        
            signVer = verify_signature(serverDir, sys.argv[1], parsed[1])

            if signVer:
                print "Signature verified and is correct"
            else:
                print "Signature not correct, file has been tampered in some way"
    else:
        with open(serverDir + '.' + sys.argv[1] + '.enc.sign', 'r') as metafile:
            first_line = metafile.readline().replace('\n','')
            parsed = first_line.split('***')
        
            signVer = verify_signature(serverDir, sys.argv[1], parsed[2])
                            
            if signVer:
                print "Signature verified and is correct"
            else:
                print "Signature not correct, file has been tampered in some way"

