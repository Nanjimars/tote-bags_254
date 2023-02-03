
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

        conn =connection() #it is needed to fetch the data in variable connect to locate the database
        sql = "Insert into messages(name,email,subject,comment) values(%s, %s, %s, %s)"
        cursor = conn.cursor()
        try:
            cursor.execute(sql, (name, email, subject, comment))
            conn.commit()
            return render_template('contact.html', msg= 'Thank you for your comment')
        except:
            return render_template('contact.html', msg= "Failed, Try again later")

    else:
        return render_template('contact.html')

# hashing the password

import hashlib, binascii, os


def hash_password(password):
    """Hash a password for storing"""
    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    password_hashed = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)

    password_hashed = binascii.hexlify(password_hashed)
    return (salt + password_hashed).decode('ascii')
# verifying hashed password


def verify_password(hashed_password, provided_password):
    """Verify a stored password against one provided by user"""
    salt = hashed_password[:64]
    hashed_password = hashed_password[64:]
    pwdhash = hashlib.pbkdf2_hmac('sha512',
                                  provided_password.encode('utf-8'),
                                  salt.encode('ascii'),
                                  100000)
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == hashed_password
    # this function hashes and salts password  using sha512 encoding


@app.route('/register', methods = ['POST', 'GET'])
def register():
    if request.method =='POST':
            username = html.escape(str(request.form['username']))
            email = html.escape(str(request.form['email']))
            password= str(request.form['password']) # passwords are usually not escaped, they are hashed
            pwd_again = str(request.form['conf_password'])

            import re
            #checks if password matches with he confirmed one
            if password!=pwd_again:
                return render_template('register.html', msg_pass = 'Passwords do not match')
            # I will add other elif statements to check the strength of the password. that now uses re.search
            else:
                conn = connection()
                sql = 'Insert into Users(username, email, password) values(%s, %s, %s)'
                cursor = conn.cursor()
                try:
                    cursor.execute(sql, (username, email, hash_password(password)))
                    conn.commit()
                    return render_template('register.html', msg_pass1 = 'Sign up successful !')
                    # if password is hashed is only when it will be stored else i will fail
                except:
                    return render_template('register.html', msg_pass2 = 'Failed, Try again later')
    else:
        return render_template('register.html')

@app.route('/login', methods = ['POST', 'GET'])
def login():
    if request.method =='POST':
        email = html.escape(str(request.form['email']))
        password = str(request.form['password'])
        conn = connection()
        sql = "Select * from Users where email=%s"
        cursor = conn.cursor()
        cursor.execute(sql, (email))
        #gets the password for the username provided in the query
        if cursor.rowcount ==0:
            return render_template('login page.html', msg= 'Login failed, User not found')
        elif cursor.rowcount ==1:
            #get password from user
            rows_found = cursor.fetchone()
            password_from_db = rows_found[2] # retrieve password from row[2], the second column in the db the=at holds passwords
            #columns are counted from zero
            status = verify_password(password_from_db, password) # call function to verify hashed password
            if status ==True:
                session["email"] = request.form['email']
                session['user_type'] = rows_found[3]
                session.permanent = True

                #Create an app logger later to tog info into a python file
                return redirect('/')
            else:
                return render_template('login page.html', msg = 'Incorrect username or password')
                # if passwords do not match
                #create an app loger
        else:
            #log something
            return render_template('login page.html', msg = 'Error Contact Support')
    else:
        return render_template('login page.html')

@app.route('/products',  methods = ['POST', 'GET'])
def add_products():
    #check if user is admin
    if "email" in session and session['user_type'] == 'admin':
        # Create a logger to inform that an admin logged in

            if request.method == 'POST':
                bag_name = html.escape(str(request.form['bag_name']))
                price = html.escape(str(request.form['price']))
                photo = request.files["photo"] #gets image file from form
                quantity = html.escape(str(request.form['quantity']))
                #read image
                readImage = photo.read()
                #encode image
                encodedImage = b64encode(readImage).decode("utf-8")
                #Send everything to the database
                conn = connection()
                sql = "Insert into Products(bag_name, price, photo, quantity) values (%s, %s, %s, %s )"
                cursor = conn.cursor()
                try:
                    cursor.execute(sql,(bag_name, price, encodedImage, quantity))
                    conn.commit()
                    return render_template('products.html', msg='Successfully Added')
                except:
                    return render_template('products.html', msg='System problem, try again later')
            else:
                return render_template('products.html')
    else:
        return redirect('/login')


@app.route('/logout')
def logout():
    session.pop("email", None)
    session.pop('usertype', None)
    return redirect('/login')

@app.route('/buy')
def view():
    if 'email' in session:
        conn = connection()
        sql = 'Select * from Products'
        cursor = conn.cursor()
        cursor.execute(sql)
        if cursor.rowcount < 1:
            return render_template('buy.html', msg_goods = 'No Products Available')
        else:
            rows = cursor.fetchall()
            return render_template('buy.html', rows=rows)

    else:
        return redirect('/login')




@app.route('/cart')
def cart():
   return render_template('cart.html')


@app.route('/restock')
def restock():
    return render_template('index.html')


if __name__ == '__main__':
   app.run(debug = True)

