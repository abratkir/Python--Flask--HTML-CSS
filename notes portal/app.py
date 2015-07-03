#encoding: utf-8
from flask import Flask, jsonify, render_template, request, session, redirect, url_for
from time import gmtime, strftime
from urllib2 import Request, urlopen, HTTPError
import json, os
import datetime
from socket import gethostname, gethostbyname 
import random 
import string
import crypt, math, time
from datetime import timedelta
from OpenSSL import SSL
context = SSL.Context(SSL.SSLv23_METHOD)
context.use_privatekey_file('testowy.key')
context.use_certificate_file('testowy.crt')

app = Flask(__name__)
app.secret_key = os.urandom(24) 
logs = {'login' : {'password' : 'abc123', 'locked' : False, 'wrongattempts' : 0}}
snippets = { 'Notatka' : {'To jest przykladowa notatka.'}}
ips = {'nazwa' : ['192.168.1.1', '192.168.0.1']}
check = {'test' : '192.168.0.1'}
logTime = "No data."
isAllowed = {'192.168.0.1' : {'attempts' : 0, 'time' : ''}}
from werkzeug.debug import DebuggedApplication
app.wsgi_app = DebuggedApplication(app.wsgi_app, evalex=True)
app.debug = True

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=2)

@app.route('/')
def index():
    if 'username' in session:
        global logTime
        if session['first'] == True :
            try:
                logTime = session['lastlogin'] 
            except KeyError:
                logTime = str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))        
            session['lastlogin'] = str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            session['first'] = False
        ips.setdefault(session['username'],[])
        ips[session['username']].append(request.environ['REMOTE_ADDR']);
        return render_template('index.html', username = session['username'], data=logTime, snippets= snippets)
    return render_template('niezalogowany.html')
	
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        isAllowed.setdefault(request.environ['REMOTE_ADDR'],{'attempts':0, 'time' : time.time()})
        if (time.time()-isAllowed[request.environ['REMOTE_ADDR']]['time'])>60:
            isAllowed[request.environ['REMOTE_ADDR']]['attempts']=0
            isAllowed[request.environ['REMOTE_ADDR']]['time']=time.time()
        if isAllowed[request.environ['REMOTE_ADDR']]['attempts']>3:
            error = 'Zablokowane IP.'
            return render_template('zaloguj.html',error=error)
        elif not checktext(request.form['username']):
            error = 'Niedozwolone znaki w loginie.'
            return render_template('zaloguj.html',error=error)
        elif not checktext(request.form['password']):
            error = 'Niedozwolone znaki w hasle.'
            return render_template('zaloguj.html',error=error)
        elif not (request.form['username'] in logs):
            error = 'Niezarejestrowany uzytkownik'
            isAllowed[request.environ['REMOTE_ADDR']]['attempts']=isAllowed[request.environ['REMOTE_ADDR']]['attempts']+1
            return render_template('zaloguj.html',error=error)
        elif (logs[request.form['username']]['locked'] == False ) and (decrypt(request.form['password'], logs[request.form['username']]['password'])):
            session['first']=True
            session['username'] = request.form['username']
            logs[request.form['username']]['locked'] = False
            return redirect(url_for('index'))
        elif (logs[request.form['username']]['locked'] == True):
            error = 'Uzytkownik zablokowany'
            return render_template('zaloguj.html',error=error)
        elif not (decrypt(request.form['password'], logs[request.form['username']]['password'])):
            isAllowed[request.environ['REMOTE_ADDR']]['attempts']=isAllowed[request.environ['REMOTE_ADDR']]['attempts']+1
            error = 'Zle haslo'
            logs[request.form['username']]['wrongattempts']= logs[request.form['username']]['wrongattempts'] + 1 
            if(logs[request.form['username']]['wrongattempts']>5):
                logs[request.form['username']]['locked'] = True
            return render_template('zaloguj.html',error=error)
        else:
            isAllowed[request.environ['REMOTE_ADDR']]['attempts']=isAllowed[request.environ['REMOTE_ADDR']]['attempts']+1
            error = 'Zle haslo'
            return render_template('zaloguj.html',error=error)
    return render_template('zaloguj.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))
	
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if not checktext(request.form['username']):
            error = 'Zabronione znaki'
            return render_template('zarejestruj.html',error=error)
        elif not checktext(request.form['password']):
            error = 'Zabronione znaki'
            return render_template('zarejestruj.html',error=error)
        elif not checktext(request.form['password2']):
            error = 'Zabronione znaki'
            return render_template('zarejestruj.html',error=error)
        elif not (request.form['password'] == request.form['password2']):
            error = 'Rozniace sie hasla'
            return render_template('zarejestruj.html',error=error)
        elif (request.form['username'] in logs):
            error = 'Uzytkownik juz istnieje w bazie danych'
            return render_template('zarejestruj.html', error=error)
        elif (request.form['username']!='') and (request.form['password']!=''):
            if request.form['entropia']<2:
                error = 'Za slabe haslo'
                return render_template('zarejestruj.html', error=error)
            logs.setdefault(request.form['username'],{'password':'', 'locked' : False, 'wrongattempts' : 0})
            logs[request.form['username']]['password']=encrypt(request.form['password'])
            isAllowed.setdefault(request.environ['REMOTE_ADDR'],{'attempts':0, 'time' : time.time()})
            session['first']=True
            session['username'] = request.form['username']
            return redirect(url_for('index'))
        else:
            error = 'Wszystkie pola musza byc wypelnione'
            return render_template('zarejestruj.html', error=error)
    return render_template('zarejestruj.html')

@app.route('/changepass', methods=['GET', 'POST'])
def changepass():
    if 'username' in session:
        if request.method == 'POST':
            if request.form['check']!=session['username']:
                error = 'Zabronione znaki loginu'
                return render_template('zmienHaslo.html',error=error, check = check[session['username']])
            elif not checktext(request.form['pass']):
                error = 'Zabronione znaki starego hasla'
                return render_template('zmienHaslo.html',error=error, check = check[session['username']])
            elif not checktext(request.form['newpass']):
                error = 'Zabronione znaki nowego hasla'
                return render_template('zmienHaslo.html',error=error, check = check[session['username']])
            elif not checktext(request.form['newpass2']):
                error = 'Zabronione znaki powtorzonego nowego hasla'
                return render_template('zmienHaslo.html',error=error, check = check[session['username']])
            elif (decrypt(request.form['pass'], logs[session['username']]['password']) and request.form['newpass'] == request.form['newpass2']):
                logs[session['username']]['password']=encrypt(request.form['newpass'])
                return redirect(url_for('index'))
            elif not (decrypt(request.form['pass'], logs[session['username']]['password'])):
                error = 'Zle podane stare haslo'
                return render_template('zmienHaslo.html', error=error, check = check[session['username']])
            elif not(request.form['newpass'] == request.form['newpass2']):
                error = 'Nowe hasla niezgodne'
                return render_template('zmienHaslo.html', error=error, check = check[session['username']])
            else:
                error = 'Wszystkie pola musza byc wypelnione'
                return render_template('zmienHaslo.html', error=error, check = check[session['username']])
        check.setdefault(session['username'],'')
        check[session['username']]=''.join([random.choice(string.letters[:26]) for i in range(15)])
        return render_template('zmienHaslo.html', check = check[session['username']])
    return redirect(url_for('index')) 
	
@app.route('/snippet', methods=['GET', 'POST'])
def snippet():
    if 'username' in session:
        if request.method == 'POST':
            if not checktext(request.form['title']):
                error = 'Zabronione znaki'
                return render_template('nowa.html',error=error, check = check[session['username']])
            elif not checktext(request.form['content']):
                error = 'Zabronione znaki'
                return render_template('nowa.html',error=error, check = check[session['username']])
            elif (request.form['title'] in snippets):
                error = 'Tytul juz byl wykorzystany'
                return render_template('nowa.html', error=error, check = check[session['username']])
            elif ('username' in session) and (request.form['title']!='') and (request.form['content']!=''):
                snippets[request.form['title']]={request.form['content'], session['username']}
                return redirect(url_for('index'))
            else:
                error = 'Wszystkie pola musza byc wypelnione'
                return render_template('nowa.html', error=error, check = check[session['username']])
        check.setdefault(session['username'],'')
        check[session['username']]=''.join([random.choice(string.letters) for i in range(15)])
        return render_template('nowa.html', check = check[session['username']])
    return redirect(url_for('index'))

def checktext(text):
    if len(text) > 1024:
        return False
    flag= True
    for i in ["<",">","[","]",";", "'", "`"]:
        if i in text:
            flag=False
            break
    return flag
	
def encrypt(password):
    salt = ''.join(random.sample(string.ascii_letters, 3))
    j = 0
    for i in range(random.randint(0, 9999)):
        j += 1
    for i in range(0, 100):
        protected_password = crypt.crypt(password, salt)
	password= protected_password
    return protected_password

def decrypt(normal_pass,crypt_pass):
    scp=crypt_pass.split("$")
    j = 0
    for i in range(random.randint(0, 9999)):
        j += 1
    for i in range(0, 100):
        cnp=crypt.crypt(normal_pass, scp[2])
        normal_pass=cnp
    if cnp.split("$")[3] in scp[3]:
        return True
    return False
	
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=6378, ssl_context=context)
