from flask import Flask
from flask import Flask, request
import os
import sys
import requests
import shutil
app = Flask(__name__)



@app.route("/check_in")
def check_in():
    client = request.args.get('client')
    fileCheckIn = request.args.get('file')
    fileSecFlag = request.args.get('sec_flag')
    
    fullPathFile = os.getcwd()+ '/clients/' + client + '/files/' + fileCheckIn
    serverDir = os.getcwd() + '/server/files/'
    if not os.path.isfile(fullPathFile):
        return "File doesn't exist. Try again please."
    else:
        shutil.copy(fullPathFile, serverDir)
        return "File exists!"

@app.route("/check_out")
def checkout():
    return 'check_out'

if __name__ == '__main__':
    app.run()
