import json
import os
from os import path as ospath
import hashlib
from flask import Flask, render_template, redirect, url_for, session, jsonify, request
from flask_wtf import Form
from wtforms import StringField, PasswordField, validators, TextField, IntegerField
from wtforms.validators import InputRequired, Length, ValidationError, EqualTo
import wtforms.validators as validators
import re
# from validation import email_in_use, passwordregex, username_in_use, checkaccount, emailuser, Emailverify
from random import randint
import smtplib
from email.message import EmailMessage
from flask_simple_geoip import SimpleGeoIP
import email_validator
import subprocess
from hashlib import sha256

path = "path/to/repoclone/"


# ---------------------------------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------------------------------
#
# -------------------------------------  form validation --------------------------------------------
#
# ---------------------------------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------------------------------




"""
------- sign up ------
"""

class Emailverify(object): # not my code - from wtforms.validators

    user_regex = re.compile(
        r"(^[-!#$%&'*+/=?^_`{}|~0-9A-Z]+(\.[-!#$%&'*+/=?^_`{}|~0-9A-Z]+)*\Z"  # dot-atom
        r'|^"([\001-\010\013\014\016-\037!#-\[\]-\177]|\\[\001-\011\013\014\016-\177])*"\Z)',  # quoted-string
        re.IGNORECASE)

    def __init__(
        self,
        message=None,
        granular_message=False,
        check_deliverability=False,
        allow_smtputf8=True,
        allow_empty_local=False,
    ):
        if email_validator is None:
            raise Exception("Install and import 'email_validator' for email validation support.")
        self.message = message
        self.granular_message = granular_message
        self.check_deliverability = check_deliverability
        self.allow_smtputf8 = allow_smtputf8
        self.allow_empty_local = allow_empty_local

    def __call__(self, form, field):
        
        try:
            if field.data is None:
                raise email_validator.EmailNotValidError()
            email_validator.validate_email(
                field.data,
                check_deliverability=self.check_deliverability,
                allow_smtputf8=self.allow_smtputf8,
                allow_empty_local=self.allow_empty_local,
            )
        except email_validator.EmailNotValidError as e:
            message = self.message
            
            if message is None:
                
                if self.granular_message:
                    message = field.gettext(e)
                else:
                    message = field.gettext("Invalid email address.")
            
            raise ValidationError(message)

def username_in_use(form, field): # wtform validator to check if username input for signup exists in /users folder
    input = field.data
    user_path = ospath.exists(path + "users/" + input + ".json")
    
    if user_path == True:
        raise ValidationError('Username already in use')

def emailexists(sendinput):
    sendinput = sendinput.lower()
    sendinput = sendinput.strip()
    
    def getusers(): # get users and parse output into clean list
        ls = subprocess.check_output(["ls", "users/"])
        split = ls.decode().split("\n")
        len1 = len(split)
        len1 = len1-int("1")
        del split[len1]
        getusers.split = split
    
    getusers()
    split = getusers.split
    
    for i in split:
        file = i
        with open(path + 'users/' + file) as f:
            jsonfull = json.load(f)
            jsonemail = jsonfull.get("email")

        if jsonemail == sendinput:
            inuse = True
            return inuse
        else:
            continue


def email_in_use(form, field):
    sendinput = field.data
    result = emailexists(sendinput)

    if result == True:
        raise ValidationError("Email already in use")
    else:
        pass

def passwordregex(form, field): # checks if password has a number and capital letter
    input = field.data
    reg = "^(?=.*[A-Z]).*"
    match_re = re.compile(reg)
    res = re.search(match_re, input)

    if res:
        pass
    else:
        raise ValidationError("Password must contain at least one capital letter and one number")

"""
------ sign in -------
"""

def emailuser(sendinput):
    sendinput = sendinput.lower()
    sendinput = sendinput.strip()

    def getusers(): # get users and parse output into clean list
        ls = subprocess.check_output(["ls", "users/"])
        split = ls.decode().split("\n")
        len1 = len(split)
        len1 = len1-int("1")
        del split[len1]
        getusers.split = split

    getusers()
    split = getusers.split

    for i in split:
        file = i
        with open(path + 'users/' + file) as f:
            jsonfull = json.load(f)
            jsonemail = jsonfull.get("email")
            jsonemail = jsonemail.lower()
            jsonemail = jsonemail.strip()

        if jsonemail == sendinput:
            file = file[:-5]
            return file
        else:
            continue

def emailuserpassword(password, username):
    username_input = username
    password_input = password

    def check_password():
        with open(path + 'users/' + username_input + '.json') as f:
            check_password_full = json.load(f)
            check_password_str = check_password_full.get("password")
        input_password_encoded = sha256(password_input.encode())
        input_password_hashed = input_password_encoded.hexdigest()

        if input_password_hashed == check_password_str:
            print("Correct Username and Password")
            check_password.loggedin = True
            pass

        else:
            print("incorrect")
            check_password.loggedin = False
            raise ValidationError("password incorrect")

    check_password()


class checkaccount(object): # not really my code but it works - gets the data from the form input specified as "object"
    def __init__(self, fieldname):
        self.fieldname = fieldname

    def __call__(self, form, field):
        try:
            other = form[self.fieldname]
        except KeyError:
            raise ValidationError(field.gettext("Invalid field name '%s'.") % self.fieldname)
        if field.data != other.data:
            
            def user_exists(): # this bit is my code - checks whether username exists. if user exists, checks password.
                username_input = other.data
                password_input = field.data
                user_path = ospath.exists(path + "users/" + username_input + ".json")
            
                def check_password():
                    with open(path + 'users/' + username_input + '.json') as f:
                        check_password_full = json.load(f)
                        check_password_str = check_password_full.get("password")
                    input_password_encoded = sha256(password_input.encode())
                    input_password_hashed = input_password_encoded.hexdigest()
            
                    if input_password_hashed == check_password_str:
                        print("Correct Username and Password")
                        check_password.loggedin = True
            
                    else:
                        print("incorrect")
                        check_password.loggedin = False
                        raise ValidationError("password incorrect")
            
                if user_path == True:
                    check_password()
            
                    if check_password.loggedin == True:
                        pass
                    elif check_password.loggedin == False:
                        pass
            
                else:
                    regex = re.compile(r"[^@]+@[^@]+\.[^@]+")
                    if not regex.match(username_input):
                        raise ValidationError("not a valid email address or user does not exist")
                    sendinput = username_input
                    result = emailuser(sendinput)
            
                    if result == None:
                        raise ValidationError("User does not exist")
                    else:
                        emailuserpassword(password=field.data, username=result)
            
            user_exists()



class CustomEqualTo(object):
    def __init__(self, fieldname, message=None):
        self.fieldname = fieldname
        self.message = message

    def __call__(self, form, field):
        try:
            other = form[self.fieldname]
        except KeyError:
            raise ValidationError(field.gettext("Invalid field name '%s'.") % self.fieldname)
        if field.data != other.data:
            d = {
                'other_label': hasattr(other, 'label') and other.label.text or self.fieldname,
                'other_name': self.fieldname
            }
            message = self.message
            if message is None:
                message = field.gettext('Passwords are not equal')

            raise ValidationError(message % d)


def oldpasswordcheck(form, self):
    password_input = form.data["oldpassword"]
    user = session["user"]
    def check_password():
        with open(path + 'users/' + user + '.json') as f:
            check_password_full = json.load(f)
            check_password_str = check_password_full.get("password")
        input_password_encoded = sha256(password_input.encode())
        input_password_hashed = input_password_encoded.hexdigest()

        if input_password_hashed == check_password_str:
            print("Correct Username and Password")
            check_password.loggedin = True

        else:
            print("incorrect")
            check_password.loggedin = False
            raise ValidationError("password incorrect")
    check_password()
    



# ---------------------------------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------------------------------
#
# -------------------------------------  MAIN APP ---------------------------------------------------
#
# ---------------------------------------------------------------------------------------------------
#
# ---------------------------------------------------------------------------------------------------


# flaskm app configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret key'
#app.secret_key = "DontTellAnyone"
app.config.update(GEOIPIFY_API_KEY='at_PCiEoWDoXB4dtIYuQr5kWp2p5yphC')
simple_geoip = SimpleGeoIP(app)

@app.route("/") # if session exists, redirects to /account. if session doesnt exist, redirects to sign in page
def index():
    if "user" in session:
        user = session["user"]
        return redirect(url_for("account"))

    else:
        return(redirect(url_for("signin")))

"""
---------- Sign in start -----------
"""

class LoginForm(Form):  # sign in form validation
    username = StringField('Email/Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired(), checkaccount("username")])

@app.route('/signin', methods=['GET', 'POST']) # compares user and password input with existing sha256 password and usernames in /users. starts user session if sign in successful
def signin():

    if "user" in session:
        return redirect(url_for("account"))
    form = LoginForm()

    if form.validate_on_submit():
        session.permanent = True
        data = form.data
        username_input = data.get("username")
        password_input = data.get("password")
        user_path = ospath.exists(path + "users/" + username_input + ".json")

        def check_password():
            with open(path + 'users/' + username_input + '.json') as f:
                check_password_full = json.load(f)
                check_password_str = check_password_full.get("password")
            input_password_encoded = hashlib.sha256(password_input.encode())
            input_password_hashed = input_password_encoded.hexdigest()

            if input_password_hashed == check_password_str:
                check_password.loggedin = True

            else:
                problem = True
                return problem

        if user_path == True:
            check_password()

            if check_password.loggedin == True:
                session["user"] = username_input
                return redirect(url_for("account"))

            elif check_password.loggedin == False:
                pass

        else:
            sendinput = username_input
            result = emailuser(sendinput)

            if result == None:
                problem = True

            else:
                session["user"] = result
                return redirect(url_for("account"))

            if problem == True:
                return redirect(url_for("problem"))

    return render_template('signin.html', form=form, mode="light")

"""
---------- Sign in end -----------


---------- Sign up start -----------
"""

class SignupForm(Form): # sign up form validation
    newusername = StringField('Username', validators=[InputRequired(), username_in_use])
    newpassword = PasswordField('Password', validators=[InputRequired(), Length(min=6, max=20), passwordregex])
    confirm = PasswordField("Confirm Password", validators=[InputRequired(), EqualTo("newpassword", "Passwords must match")])
    email = StringField("Email", validators=[Emailverify(message=None, granular_message=False, check_deliverability=False, allow_smtputf8=True, allow_empty_local=False), email_in_use])

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm()

    if form.validate_on_submit():
        data = form.data
        username = data.get("newusername")
        password = data.get("newpassword")
        email = data.get("email")

        def new_account():
            password_input = password
            input_password_encoded = hashlib.sha256(password_input.encode())
            input_password_hashed = input_password_encoded.hexdigest()
            password_json_write = {"password": "" + input_password_hashed + "", "email": "" + email + ""}
            with open(path + "users/" + username + ".json", 'w') as f:
                json.dump(password_json_write, f)

        new_account()

    return render_template("signup.html", form=form)

"""
---------- Sign up end -----------


-------- account required -------
"""

@app.route("/account") # displays signedin.html page if user exists. if user doesnt exist, redirects to signin page
def account():
    if "user" in session:
        user = session["user"]
        return render_template("signedin.html", data_username=user)
    else:
        return redirect(url_for("signin"))

@app.route("/googlesheets")
def googlesheets():
    if "user" in session:
        user = session["user"]
        return render_template("googlesheets.html")
    else:
        return redirect(url_for("signin"))

@app.route("/weather")
def weather():
    if "user" in session:
        data = request.headers['X-Real-IP']
        return data
    else:
        return redirect(url_for("signin"))

@app.route("/settings")
def settings():
    if "user" in session:
        user = session["user"]
        return render_template("settings.html")
    else:
        return redirect(url_for("signin"))

class changepasswordform(Form):
    oldpassword = PasswordField("Old Password", validators=[InputRequired(), oldpasswordcheck])
    newpassword = PasswordField("New Password", validators=[InputRequired(), Length(min=6, max=20), passwordregex])
    confirm = PasswordField("Confirm Password", validators=[InputRequired(), CustomEqualTo("newpassword")])

@app.route("/changepassword", methods=["GET", "POST"])
def changepassword():
    
    if "user" in session:
        changepassform = changepasswordform()
        user = session["user"]
        
        if changepassform.validate_on_submit():
            data = changepassform.data
            newpasswordinput = data.get("newpassword")
            
            def alterpassword():
                
                def jsonrecieve():
                    with open(path + 'users/' + user + '.json') as f:
                        fulljson = json.load(f)
                        print(fulljson)
                        return fulljson
                
                def jsonupdate():
                    jsonoutput = jsonrecieve()
                    input_password_encoded = hashlib.sha256(newpasswordinput.encode())
                    input_password_hashed = input_password_encoded.hexdigest()
                    print(input_password_hashed)
                    jsonoutput["password"] = input_password_hashed
                    filewrite = open(path + 'users/' + user + '.json', "w")
                    json.dump(jsonoutput, filewrite)
                    filewrite.close()
                
                jsonupdate()
            
            alterpassword()
            return redirect(url_for("settings"))
    else:
        return redirect(url_for("signin"))

    return render_template("changepassword.html", form=changepassform)



"""
---------- other --------
"""

@app.route("/signout") # removes session info and redirects user to sign in page
def signout():
    session.pop("user", None)
    return redirect(url_for("signin"))

@app.route("/problem")
def problem():
    return "oops, a problem occured \nplease contact tmarshy2006@gmail.com for support"

@app.errorhandler(404)
def not_found(e):
    return render_template("404.html")

if __name__ == '__main__':
    app.run(debug=True, host = "0.0.0.0") # puts webserver up to lan and reloads server when save file





