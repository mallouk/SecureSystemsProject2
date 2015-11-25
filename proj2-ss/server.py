from flask import Flask
app = Flask(__name__)

@app.route("/checkin")
def checkin():
    name = request.args.get('name')
    fileName = request.files('file')
    return 'Hello World'

@app.route("/checkout")
def checkout():
    return 'checkout'

@app.route("/")
def index():
    return 'index'

if __name__ == '__main__':
    app.run()
