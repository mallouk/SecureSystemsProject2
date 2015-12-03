from flask import Flask
from flask import Flask, request, redirect, url_for
from werkzeug import secure_filename
import os, sys, requests, string, random, struct
UPLOAD_FOLDER = 'joe'


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/test', methods=['POST'])
def test():
    #print request.stream
#    data = request.args.get('enc_type')
    print request.values
    print request.form
    print request.args
    if request.method == 'POST':
        print 'joe'
        file = request.files['file']
        print 'hugh'
        if file:
            print 'blah'
            filename = secure_filename(file.filename)
            print os.path
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            print 'fofowfjwof'
        return 'moo'
    return 'boo'

if __name__ == '__main__':
    app.run()
