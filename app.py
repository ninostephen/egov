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
from flask import render_template
from flask_mysqldb import MySQL
from uuid import uuid4
from json import dumps
from functools import wraps
from base64 import b64encode
from collections import OrderedDict
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
app.config['MYSQL_USER'] = 'admin'
app.config['MYSQL_PASSWORD'] = 'password'
app.config['MYSQL_DB'] = 'egov'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

# Database Object
mysql = MySQL(app)

chain = Blockchain()

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
    session.clear()
    return redirect(url_for("userLogin"))

@app.route('/official/signout', methods = ['GET','POST'])
def signoutOfficial():
    session.clear()
    return redirect(url_for("officialLogin"))

@app.route('/admin/signout', methods = ['GET','POST'])
def signoutAdmin():
    session.clear()
    return redirect(url_for("adminLogin"))

# User Pages
@app.route('/user/login', methods = ['GET', 'POST'])
def userLogin():
    if request.method == 'POST':
        username = request.form['username']
        passwordCandidate = request.form['pwd']

        query = "SELECT * FROM users where username = '" + username +"';"
#        app.logger.info(query)
        cursor = mysql.connection.cursor()
        results = cursor.execute(query)
        if results > 0 :
            data = cursor.fetchone()
            password = data['password']
            #Compare Passwords
            if sha256_crypt.verify(passwordCandidate, password):
                session['loggedIn'] = True
                session['username'] = data['username']
                session['name'] = data['name']
                session['userid'] = data['userid']
                session['rid'] = False
                session['update'] = False
#                session['secret_key'] = str(uuid4()).replace("-","") + str(uuid4()).replace("-","")

                return redirect(url_for('apply'))
            else :
                error = 'Invaid Username or Password'
                app.logger.error(error)
                return redirect(url_for('userLogin'))
        else :
            error = 'Invaid Username or Password'
            app.logger.error(error)
            return redirect(url_for('userLogin'))
        return render_template('user/login.html')
    return render_template('user/login.html')



@app.route('/user/signup', methods = ['GET', 'POST'])
def registerUser():
    if request.method == 'POST':
        name = request.form['fname']
        username = request.form['uname']
        password = request.form['pwd']
        password = sha256_crypt.hash(password)
        #confirm = request.form['cpwd']

        #generate wallet address UUID
        _ = keyGen(username=username, type='user')
        userid = generateWalletAddr(username=username, type='user')
#        app.logger.info(userid)
#        app.logger.info(username)
#        app.logger.info(password)
#        app.logger.info(name)
        cursor = mysql.connection.cursor()
        query = 'INSERT INTO users(userid,username,name, password) VALUES ( "' + userid + '","' + username + '","' + name + '","' + password + '");'
#        app.logger.info(query)
        result = cursor.execute(query)
#        app.logger.info(result)
        mysql.connection.commit()
        type = 'user'
        publicKey = getPublicKey(username=username, type='user').decode('utf-8')
        query = 'INSERT INTO userKeys(userid,type,publilcKey) VALUES ( "' + userid + '","' + type + '","' + publicKey + '");'
#        app.logger.info(query)
        result = cursor.execute(query)
#        app.logger.info(result)
        mysql.connection.commit()
        cursor.close()
        if result :
            return redirect(url_for('userLogin'))
        return render_template('user/signup.html')
    return render_template('user/signup.html')

@app.route('/user/application/<requestId>', methods = ['GET', 'POST'])
@isUserLoggedIn
def application(requestId):
    app.logger.info('application method')
    app.logger.info(requestId)
    session['rid'] = requestId
    session['update'] = True
    return redirect(url_for('apply'))



@app.route('/', methods = ['GET', 'POST'])
@app.route('/user/', methods = ['GET', 'POST'])
@app.route('/user/apply', methods = ['GET', 'POST'])
@isUserLoggedIn
def apply():
#    UNITS = ['iedc', 'nss', 'ieee', 'technocratz']s

    if request.method == 'POST':
        if session['rid']:
            requestId = session['rid']
            app.logger.info(requestId)
            query = "SELECT subject,unit,body from request where requestId ='" + requestId + "';"
            app.logger.info(query)
            cursor = mysql.connection.cursor()
            cursor.execute(query)
            record = cursor.fetchone()
            app.logger.info(record)
            subject = record['subject']
            unit = record['unit']
            content = record['body']
            cursor.close()
            session['requestId'] = requestId
            session['rid'] = False

            return render_template('user/apply.html', subject=subject, unit=unit, content=content)
        else:
            subject = request.form['subject']
            unit = request.form['unit']
            content = request.form['content']
            checker = request.form['checker']
            cursor = mysql.connection.cursor()
    #        app.logger.info(subject)
    #        app.logger.info(unit)
    #        app.logger.info(content)
    #        app.logger.info(checker)
            userid = session['userid']
            comments = "null"
            integrity = "Invaid"
            #app.logger.info(values)
            if 'sign' in checker :
                session['signed'] = "not signed"
                requestId = str(uuid4()).replace("-","")
                app.logger.info('sign')
                data = OrderedDict({
                    "subject" : subject,
                    "unit" : unit,
                    "content" : content
                })
                dHash = chain.getTHash(dumps(data).encode('ascii'))
                session[requestId] = dHash
                session["1"] = requestId
                session['valid'] = "valid"
                session['signed'] = "signed"
                app.logger.info(requestId)
                app.logger.info(dHash)
                return render_template('user/apply.html', subject=subject, unit=unit, content=content)
            elif 'draft' in checker :
                app.logger.info('draft')
                session['signed'] = "not signed"
                status = session['signed']
                requestId = session["1"]
                integrity = "Invaid"
                session['valid'] = integrity
                proof = "Not Defined"
                query = 'INSERT INTO request(requestID, userid, unit, subject, body, status, comments, integrity, proof) VALUES ( "' + requestId + '", "' + userid + '","' + unit + '","' + subject + '","' + content + '","' + status + '","' + comments + '","' + integrity + '","' + proof + '");'
                app.logger.info(query)
                try:
                    cursor.execute(query)
                    mysql.connection.commit()
                    cursor.close()
                except Exception as e:
                    app.logger.error(e)
                return redirect(url_for('draft'))
            else :
                status = session['signed']
                requestId = session["1"]
                proof = session[requestId]
                query1 = 'INSERT INTO request(requestID, userid, unit, subject, body, status, comments, integrity, proof) VALUES ( "' + requestId + '", "' + userid + '","' + unit + '","' + subject + '","' + content + '","' + status + '","' + comments + '","' + integrity + '","' + proof + '");'
                query2 = 'INSERT INTO requestStatus(requestId, officialId, action) VALUES("'+ requestId + '", "Not assigned", "applied")'
                app.logger.info(session['update'])
                if session['update'] == True:
                    query1 = 'UPDATE request SET status="signed", integrity="valid" where requestId="' + requestId + '";'
                app.logger.info(query1)
                app.logger.info('submit')
                try:
                    cursor.execute(query1)
                    cursor.execute(query2)
                    mysql.connection.commit()
                    cursor.close()
                except Exception as e:
                    app.logger.error(e)
                session['signed'] = "not signed"
                return render_template('user/apply.html')
    return render_template('user/apply.html')

@app.route('/user/delete', methods = ['POST'])
@isUserLoggedIn
def deleteRequest():
    requestId = request.form['requestId']
    cursor = mysql.connection.cursor()
    query = "DELETE FROM request where requestId = '" + requestId +"';"
    app.logger.info(query)
    cursor.execute(query)
    mysql.connection.commit()
    cursor.close()
    return redirect(url_for('draft'))

@app.route('/user/draft', methods = ['GET', 'POST'])
@isUserLoggedIn
def draft():
    cursor = mysql.connection.cursor()
    query = "SELECT requestId, subject, submisionDate from request where integrity='Invaid' or status = 'not signed';"
    app.logger.info(query)
    cursor.execute(query)
    records = cursor.fetchall()
#    mysql.connection.commit()
    cursor.close()
#    for count,row in enumerate(records):
#        app.logger.info(count)
#        app.logger.info(row)
    return render_template('user/draft.html', records=records)

@app.route('/user/status', methods = ['GET', 'POST'])
@isUserLoggedIn
def status():
    cursor = mysql.connection.cursor()
    query = "SELECT request.requestId, subject, comments, action, actionTime from request, requestStatus where request.requestId = requestStatus.requestId;"
    app.logger.info(query)
    cursor.execute(query)
    records = cursor.fetchall()
    app.logger.info(records)
#    mysql.connection.commit()
    cursor.close()
    return render_template('user/status.html', records = records)



@app.route('/user/settings', methods = ['GET', 'POST'])
@isUserLoggedIn
def settings():
    return render_template('user/settings.html')




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
#    result = cur.execute("SELECT * FROM  reqlist LIMIT 10")
#    if result > 0:
#        reqlist = []
#        data = cur.fetchall()
#        for item in data:
#            reqlist.append(item)
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


if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug = True)
