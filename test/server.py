from flask import Flask
from flask import Flask, request, redirect, url_for
from werkzeug import secure_filename
import os, sys, requests, string, random, struct
UPLOAD_FOLDER = '/home/matthew/test/joe'


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/test', methods=['GET', 'POST'])
def test():
    print request.stream
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path(app.config['UPLOAD_FOLDER'], filename))
        return 'moo'
    return 'boo'

if __name__ == '__main__':
    app.run()
