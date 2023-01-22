
from base64 import b64encode #to encode the image
from datetime import timedelta # used on

from flask import Flask, render_template, session

# to allow logging
# import logging
# logging.basicConfig(filename = 'demo.log', level=logging.DEBUG)
# start a flask app
app = Flask(__name__)
 # set key to encrypt sessions/token
app.secret_key ='Totebags&hats'
 #used for CSRF protection
# from flask_wtf.csrf import CsrfProtect
# csrf = CsrfProtect(app)

#import flask redirect,request
from flask import redirect
from flask import request

#Set seesion expiry lifetime if not in use, here it is 5 mins
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes = 5)

#activate HTTP Only/Secure to True
#activate samesite to 'Lax'
#This reduces chances of a session fixation/hijacking
app.config.update(
    SESSION_COOKIE_SECURE = False, #For it to work locally
    SESSION_COOKIE_HTTPONLY = True,
    SESSION_COOKIE_SAMESITE = 'Lax'
)

@app.route('/')
def home():
    return render_template('index.html')

app.route('/contact_page')
def contact():
    return  render_template('contact.html')
if __name__ == '__main__':
   app.run(debug = True)

