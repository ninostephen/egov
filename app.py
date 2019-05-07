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
from datetime import datetime
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
            return redirect(url_for('userLogin'))
    return wrap


# Check if user logged in
def isOfficialLoggedIn(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'loggedIn' in session :
            return f(*args, **kwargs)
        else :
            return redirect(url_for('officialLogin'))
    return wrap


# Check if user logged in
def isAdminLoggedIn(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'loggedIn' in session :
            return f(*args, **kwargs)
        else :
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
        app.logger.info(query)
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
        cursor = mysql.connection.cursor()
        query = 'INSERT INTO users(userid,username,name, password) VALUES ( "' + userid + '","' + username + '","' + name + '","' + password + '");'
        app.logger.info(query)
        result = cursor.execute(query)
        mysql.connection.commit()
        type = 'user'
        publicKey = getPublicKey(username=username, type='user').decode('utf-8')
        query = 'INSERT INTO userKeys(userid,type,publicKey) VALUES ( "' + userid + '","' + type + '","' + publicKey + '");'
        app.logger.info(query)
        result = cursor.execute(query)
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
                query2 = 'SELECT officialId FROM officials where grade = "1" and unit = "' + unit +'";'

                app.logger.info(query2)
                cursor.execute(query2)
                records = cursor.fetchone()
                officialId = records['officialId']
                query3= 'INSERT INTO requestStatus(requestId, officialId, action) VALUES("'+ requestId + '", "' + officialId +'", "applied");'

                if session['update'] == True:
                    query1 = 'UPDATE request SET status="signed", integrity="valid" where requestId="' + requestId + '";'
                app.logger.info(query1)
                app.logger.info('submit')
                try:
                    cursor.execute(query1)

                    cursor.execute(query3)
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
    cursor.close()
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
    cursor.close()
    return render_template('user/status.html', records = records)


@app.route('/user/settings', methods = ['GET', 'POST'])
@isUserLoggedIn
def settings():
    if request.method == "POST":
        checker = request.form['checker']
        app.logger.info(checker)
        if checker == "changePwd":
            password = request.form['opassword']
            newPassord = request.form['npassword']
            confirm = request.form['cpassword']
            if newPassord == confirm:
                cursor = mysql.connection.cursor()
                query = "SELECT password FROM users where username = '" + session['username'] + "';"
                app.logger.info(query)
                cursor.execute(query)
                record = cursor.fetchone()
                hash = record['password']
                app.logger.info(hash)
                app.logger.info(sha256_crypt.hash(password))
                if sha256_crypt.verify(password, hash) :
                    query = "UPDATE users SET password ='" + sha256_crypt.hash(newPassord) +"' WHERE username = '" + session['username'] + "';"
                    cursor.execute(query)
                    mysql.connection.commit()
                    cursor.close()
        elif checker == "changeKey":
            query = "UPDATE userKeys SET deprication ='" + datetime.now().isoformat().split('T')[0] +"' WHERE userid = '" + session['userid'] + "' and deprication = 'NULL';"
            app.logger.info(query)
            cursor = mysql.connection.cursor()
            cursor.execute(query)
            mysql.connection.commit()
            type = 'user'
            _ = keyGen(username = session['username'], type = type)
            publicKey = getPublicKey(username=session['username'], type='user').decode('utf-8')
            query = 'INSERT INTO userKeys(userid,type,publicKey) VALUES ( "' + session["userid"] + '","' + type + '","' + publicKey + '");'
            app.logger.info(query)
            cursor.execute(query)
            mysql.connection.commit()
            cursor.close()
        elif checker == '2FA':
            email = request.form['email']
            phone = request.form['number']
            query = "INSERT INTO settings(userid, phone, email, temporaryCode) VALUES('" + session['userid'] +"' , '"+ phone +"' , '"+ email +"' , '"+ str(uuid4()).replace("-","")[0:6] +"');"
            app.logger.info(query)
            cursor = mysql.connection.cursor()
            cursor.execute(query)
            mysql.connection.commit()
            cursor.close()
        else:
            pass
        return render_template('user/settings.html')
    return render_template('user/settings.html')


# Official Pages

@app.route('/official/login', methods = ['GET', 'POST'])
def officialLogin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        secret = request.form['key']
        cursor = mysql.connection.cursor()
        query = "SELECT * FROM officials where email = '" + email + "' and type='official';"
        results = cursor.execute(query)
        if results > 0 :
            data = cursor.fetchone()
            hash = data['password']
            #Compare Passwords
            if sha256_crypt.verify(password, hash):
                session['loggedIn'] = True
                session['email'] = data['email']
                session['name'] = data['name']
                session['officialId'] = data['officialId']
                session['unit'] = data['unit']
                session['grade'] = data['grade']
                session['type'] = data['type']
                session['rid'] = False
                return redirect(url_for('reqList'))
            else :

                return redirect(url_for('officalLogin'))
        else :

            return redirect(url_for('reqList'))
        return render_template('official/officialslogin.html')
    return render_template('official/officialslogin.html')


@app.route('/official/', methods = ['GET', 'POST'])
@app.route('/official/list', methods = ['GET', 'POST'])
@isOfficialLoggedIn
def reqList():
    #select users.name, request.submisionDate, request.subject, request.requestID, requestStatus.action, officials.grade from users, request, requestStatus, officials where users.userid = request.userid and request.requestID = requestStatus.requestId and request.unit = officials.unit and grade = "3" and request.unit = "IEDC";
    query =  "SELECT users.name, request.submisionDate, request.subject, requestStatus.requestId, requestStatus.action, officials.grade FROM users, request, requestStatus, officials WHERE users.userid = request.userid and request.requestID = requestStatus.requestId and officials.officialId = requestStatus.officialId and request.unit = officials.unit and officials.grade = '" + str(session['grade']) +"' and request.unit = '" + session['unit'] +"';"
    app.logger.info(query)
    cursor = mysql.connection.cursor()
    cursor.execute(query)
    records = cursor.fetchall()
    app.logger.info(records)
    return render_template('official/requestlist.html', records=records)

@app.route('/official/view/<requestId>', methods = ['GET','POST'])
@isOfficialLoggedIn
def getRequest(requestId):
    app.logger.info("getRequest method")
    app.logger.info(requestId)
    session['rid'] = requestId
    session['requestId'] = requestId
    return redirect(url_for('reqView'))

@app.route('/official/view/', methods = ['GET', 'POST'])
@isOfficialLoggedIn
def reqView():
    if session['rid']:
        session['signed'] = "not signed"
        query =  "SELECT subject, submisionDate, body FROM request WHERE requestId ='" + session['rid'] +"';"
        app.logger.info(query)
        cursor = mysql.connection.cursor()
        cursor.execute(query)
        records = cursor.fetchone()
        session['rid'] = False
        session['records'] = records
        app.logger.info(records)
        return render_template('official/requestview.html', records=records)

    if request.method ==  "POST":
        app.logger.info('POST Section')
        comments = request.form['comments']
        action = request.form['option']
        checker = request.form['checker']
        app.logger.info('CHECKER')
        app.logger.info(checker)
        app.logger.info('SIGN VALUE')
        app.logger.info(session['signed'])
        if checker == 'sign':
            app.logger.info(session['records'])
            data = OrderedDict({
                "comments" : comments,
                "action" : action,
                "signer" : session['officialId'],
                "requestId" : session['requestId']
            })
            dHash = chain.getTHash(dumps(data).encode('ascii'))
            requestId = session['requestId']
            session[requestId] = dHash
            session['valid'] = "valid"
            session['signed'] = "signed"
            app.logger.info(requestId)
            app.logger.info(dHash)

            return render_template('official/requestview.html',records=session['records'],comments=comments,action=action)
        elif checker == "submit" :
            app.logger.info('Submit Section')
            requestId = session['requestId']
            proof = session[requestId]
            query1 = "UPDATE request SET comments = '" + request.form['comments'] + "', proof = '" + proof + "' WHERE requestId = '" + session['requestId'] + "' ;"
            cursor = mysql.connection.cursor()
            app.logger.info('query1')
            app.logger.info(query1)
            cursor.execute(query1)
            mysql.connection.commit()

            grade = session['grade']
            if grade > 2 or action == 'Drop':
                app.logger.info('if section')
                session['newOfficial'] = session['officialId']

            else:
                app.logger.info('else section')

                grade = grade + 1
                query2 = "SELECT officialId,grade,name FROM officials WHERE unit = '" + session['unit'] + "' and grade = '" + str(grade)  + "';"
                app.logger.info('query2')
                app.logger.info(query2)
                cursor.execute(query2)
                record = cursor.fetchone()
                app.logger.info(record)
                session['newOfficial'] = record['officialId']

            query3 = "UPDATE requestStatus SET officialId = '" + session['newOfficial'] +"', action = '" + action + "', actionTime ='" + datetime.now().isoformat() + "'  WHERE requestId = '" + session['requestId'] + "' ;"

            app.logger.info('query3')
            app.logger.info(query3)
            cursor.execute(query3)
            mysql.connection.commit()
            cursor.close()

            return redirect(url_for('reqList'))
        else:
            pass



@app.route('/official/settings', methods = ['GET', 'POST'])
@isOfficialLoggedIn
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
        name = request.form['name']
        unit =request.form['unit']
        email = request.form['email']
        type = request.form['type']
        grade = request.form['grade']
        password = request.form['password']
        app.logger.info(type)
        secret = str(uuid4()).replace("-","")[0:6]
        password = sha256_crypt.hash(password)
        keyGen(username=email, type=type)
        officialId = generateWalletAddr(username=email, type=type)
        cursor = mysql.connection.cursor()
        query = "INSERT INTO officials(officialId, name, unit, email, password, secret, type, grade) VALUES('" + officialId+ "', '" + name + "', '" + unit + "', '" + email + "', '" + password + "', '" + secret + "', '" + type + "', '" + grade + "');"
        app.logger.info(query)
        cursor.execute(query)
        mysql.connection.commit()

        publicKey = getPublicKey(username=email, type=type).decode('utf-8')
        query = 'INSERT INTO userKeys(userid,type,publicKey) VALUES ( "' + officialId + '","' + type + '","' + publicKey + '");'
        app.logger.info(query)
        result = cursor.execute(query)
        mysql.connection.commit()

        cursor.close()
        return render_template('admin/register.html')
    return render_template('admin/register.html')


if __name__ == '__main__':
    app.secret_key = 'secret123'
    app.run(debug = True)
