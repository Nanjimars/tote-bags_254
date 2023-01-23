
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
#connecting to the database
import pymysql
import html #for html escaping
@app.route('/')
def home():
    return render_template('index.html')
#Comnnecting to the database
def connection():
    server = 'localhost'
    database = 'Tote_254'
    user = 'root'
    password = ''
    conn = pymysql.connect(host = server, user = user, password= password, database=database)
    return conn


@app.route('/contact',  methods=['POST', 'GET'])
def contact():
    if request.method =='POST':
        name = html.escape(str(request.form['name']))
        email = html.escape(str(request.form['email']))
        subject = html.escape(str(request.form['subject']))
        comment = html.escape(str(request.form['comment']))

        conn =connection() # change this later to have a variable on its own
        sql = "Insert into messages(name,email,subject,comment ) values(%s, %s, %s, %s)"
        cursor = conn.cursor()
        #try:
        cursor.execute(sql, (name, email, subject, comment))
        conn.commit()
        return render_template('contact.html', msg= 'Thank you for your comment')
       # except:
            #return render_template('contact.html', msg= "Failed, Try again later")

    else:
        return render_template('contact.html')


if __name__ == '__main__':
   app.run(debug = True)

