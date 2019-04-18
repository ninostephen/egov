#!/usr/bin/python3

# Developed by Nino Stephen Mathew ( ninosm12[at]gmail[dot]com )
# Main Application Module

from flask import Flask
from flask import flash
from flask import request
from flask import redirect
from flask import url_for
from flask import session
from flask import logging
from flask import session
from flask import render_template
from flask_mysqldb import MySQL
from uuid import uuid4
from json import dumps
from functools import wraps
from passlib.hash import sha256_crypt

from blockchain  import Blockchain
from blockCrypto import keyGen
from blockCrypto import getPublicKey
from blockCrypto import signTransaction
from blockCrypto import verifyTransaction
from blockCrypto import generateWalletAddr

app = Flask(__name__)

# Database Configs
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'egov'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Database Object
mysql = MySQL(app)

#blockchain = Blockchain()

# Check if user logged in
def isUserLoggedIn(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'loggedIn' in session :
            return f(*args, **kwargs)
        else :
#            flash('Unauthorised. Please Login','danger')
            return redirect(url_for('userLogin'))
    return wrap

# Check if user logged in
def isOfficialLoggedIn(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'loggedIn' in session :
            return f(*args, **kwargs)
        else :
#            flash('Unauthorised. Please Login','danger')
            return redirect(url_for('officialLogin'))
    return wrap

# Check if user logged in
def isAdminLoggedIn(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'loggedIn' in session :
            return f(*args, **kwargs)
        else :
#            flash('Unauthorised. Please Login','danger')
            return redirect(url_for('adminLogin'))
    return wrap

# Common Signout
@app.route('/user/signout', methods = ['GET','POST'])
def signoutUser():
#    session.destroy()
    return redirect(url_for("userLogin"))

@app.route('/official/signout', methods = ['GET','POST'])
def signoutOfficial():
#    session.destroy()
    return redirect(url_for("officialLogin"))

@app.route('/admin/signout', methods = ['GET','POST'])
def signoutAdmin():
#    session.destroy()
    return redirect(url_for("adminLogin"))

# User Pages
@app.route('/user/login', methods = ['GET', 'POST'])
def userLogin():
    if request.method == 'POST':
        username = request.form['username']
        passwordCandidate = request.form['password']

        cursor = mysql.connection.cursor()
        results = cursor.execute("SELECT * FROM userLogin where username = %s",[username])
        if results > 0 :
            data = cur.fetchone()
            password = data['password']
            #Compare Passwords
            if sha256_crypt.verify(passwordCandidate, password):
                session['loggedIn'] = True
                session['username'] = username
                session['secret_key'] = str(uuid4()).replace("-","") + str(uuid4()).replace("-","")

                return redirect(url_for('apply'))
            else :
                error = 'Invaid Username or Password'
                return redirect(url_for('userLogin'))
        else :
            error = 'Invaid Username or Password'
            return redirect(url_for('userLogin'))
        return render_template('user/login.html')
    return render_template('user/login.html')



@app.route('/user/signup', methods = ['GET', 'POST'])
def registerUser():
    return render_template('user/signup.html')

@app.route('/user/', methods = ['GET', 'POST'])
@app.route('/user/apply', methods = ['GET', 'POST'])
#@isUserLoggedIn
def apply():
    UNITS = ['iedc', 'nss', 'ieee', 'technocratz']
    if request.method == 'POST':
        subject = request.form['subject']
        unit = request.form['unit'].lower()
        content = request.form['content']
        cursor = mysql.connection.cursor()

        if 'sign' in request.form :
            pass
        elif 'draft' in request.form :
            pass
        elif 'submit' in request.form :
            transaction = {
            'subject' : subject,
            'content' : content,
            'unit' : unit
            }
            r, s, transactionData = signTransaction(username='nino', transactionData=dumps(transactionData), type='user')
            query = "INSERT INTO request(reqId, unit, requesteeId, reqHeading, content, s, r) VALUES ({reqId}, {unit}, {requesteeId}, {reqHeading}, {content}, {s}, {r})".format(reqId = str(uuid4()).replace("-","") , unit=unit, requesteeId=0, reqHeading=subject, content=content, s=s, r=r)
            try:
                cursor.execute(query)
            except Exception as e:
                print(e)
        else:
            return render_template('user/apply.html')
    return render_template('user/apply.html')

@app.route('/user/draft', methods = ['GET', 'POST'])
#@isUserLoggedIn
def draft():
    return render_template('user/draft.html')

@app.route('/user/settings', methods = ['GET', 'POST'])
#@isUserLoggedIn
def settings():
    return render_template('user/settings.html')


@app.route('/user/status', methods = ['GET', 'POST'])
#@isUserLoggedIn
def status():
    return render_template('user/status.html')

#@app.route('/user/documents', methods = ['GET', 'POST'])
#@isUserLoggedIn
#def documents():
#    return render_template('user/getdoc.html')

# Official Pages

@app.route('/official/login', methods = ['GET', 'POST'])
def officialLogin():
    if request.method == 'POST':
        username = request.form['username']
        passwordCandidate = request.form['password']

        cursor = mysql.connection.cursor()
        results = cursor.execute("SELECT * FROM officalLogin where username = %s",[username])
        if results > 0 :
            data = cur.fetchone()
            password = data['password']
            #Compare Passwords
            if sha256_crypt.verify(passwordCandidate, password):
                session['loggedIn'] = True
                session['username'] = username
                session['secret_key'] = str(uuid4()).replace("-","") + str(uuid4()).replace("-","")

                return redirect(url_for('reqList'))
            else :
                error = 'Invaid Username or Password'
                return redirect(url_for('officalLogin'))
        else :
            error = 'Invaid Username or Password'
            return redirect(url_for('reqList'))
        return render_template('official/officialslogin.html')
    return render_template('official/officialslogin.html')

@app.route('/official/', methods = ['GET', 'POST'])
@app.route('/official/list', methods = ['GET', 'POST'])
#@isOfficialLoggedIn
def reqList():
    if request.method == 'POST':
        return render_template('official/requestlist.html')
    cur = mysql.connection.cursor()
    result = cur.execute("SELECT * FROM  reqlist LIMIT 10")
    if result > 0:
        reqlist = []
        data = cur.fetchall()
        for item in data:
            reqlist.append(item)
    return render_template('official/requestlist.html')

@app.route('/official/view/', methods = ['GET', 'POST'])
@app.route('/official/view/<int:reqid>', methods = ['GET', 'POST'])
#@isOfficialLoggedIn
def reqView():
    if request.method == 'POST':
        return render_template('official/requestview.html')
    return render_template('official/requestview.html')


@app.route('/official/settings', methods = ['GET', 'POST'])
#@isOfficialLoggedIn
def officialSettings():
    if request.method == 'POST':
        return render_template('official/settings.html')
    return render_template('official/settings.html')

#@app.route('/official/documents', methods = ['GET', 'POST'])
#@isOfficialLoggedIn
#def officialDocs():
#    if request.method == 'POST':
#        return render_template('official/document.html')
#    return render_template('official/document.html')

# Admin Panel

@app.route('/admin/login', methods = ['GET', 'POST'])
def adminLogin():
    if request.method == 'POST':
        return render_template('admin/adminlogin.html')
    return render_template('admin/adminlogin.html')

@app.route('/admin/', methods = ['GET', 'POST'])
@app.route('/admin/manage', methods = ['GET', 'POST'])
#@isAdminLoggedIn
def manageNodes():
    if request.method == 'POST':
        if request.form['Add'] == 'Add':
            pass
        elif request.form['Edit'] == 'Edit':
            pass
        elif request.form['Delete'] == 'Delete':
            pass

        return render_template('admin/node.html')
    return render_template('admin/node.html')

@app.route('/admin/settings', methods = ['GET', 'POST'])
#@isAdminLoggedIn
def adminSettings():
    if request.method == 'POST':
        return render_template('admin/settings.html')
    return render_template('admin/settings.html')


@app.route('/admin/register', methods = ['GET', 'POST'])
#@isAdminLoggedIn
def regOfficial():
    if request.method == 'POST':

        return render_template('admin/register.html')
    return render_template('admin/register.html')

#@app.route('/admin/debuguser', methods = ['GET', 'POST'])
#@isAdminLoggedIn
#def debuguser():
#    if request.method == 'POST':
#        return render_template('admin/debug.html')
#    return render_template('admin/debug.html')

#@app.route('/admin/list', methods = ['GET', 'POST'])
#@isAdminLoggedIn
#def adminReq():
#    if request.method == 'POST':
#        return render_template('admin/requestlist.html')
#    return render_template('admin/requestlist.html')

#@app.route('/admin/view', methods = ['GET', 'POST'])
#@isAdminLoggedIn
#def adminViewReq():
#    if request.method == 'POST':
#        return render_template('admin/requestview.html')
#    return render_template('admin/requestview.html')

if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug = True)
