from flask import Flask, render_template, request, redirect, flash, session
from mysqlconnection import connectToMySQL
import re	# the regex module
from flask_bcrypt import Bcrypt        
# create a regular expression object that we'll use later   
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
app = Flask(__name__)
app.secret_key = "super secret"
bcrypt = Bcrypt(app)

@app.route("/")
def index():
    if 'submitted' in session:
        pass
    else:
        session['submitted'] = {}
    form_vals = session['submitted']

    return render_template("index.html", form_vals = form_vals)

@app.route("/reg-verification", methods=['POST'])
def verify_email():
    is_valid = True
    #first verify if everything returns true:
    if not str.isalpha(request.form['first_name']) or len(request.form['first_name']) < 2:
        is_valid = False
        flash("First name must contain at least 2 letters and contain only letters", 'reg_fname')
    print ("*"*50, "\nisalpha: ", str.isalpha(request.form['first_name']), "\nForm data: ", request.form['first_name'], "\nForm length: ", len(request.form['first_name']))
    if not str.isalpha(request.form['last_name']) or len(request.form['last_name']) < 2:
        is_valid = False
        flash("Last name must contain at least 2 letters and contain only letters", 'reg_lname')
    if not EMAIL_REGEX.match(request.form['email']):    # test whether a field matches the pattern
        is_valid = False
        flash("Invalid email address!", 'reg_email')
    print(request.form['email'])
    if not bool(re.match('^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])', request.form['password'])) or len(request.form['password']) > 14 or len(request.form['password']) < 7:
        is_valid = False
        print(bool(re.match('^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])', request.form['password'])), request.form['password'])
        flash("Password must contain a number, a capital letter, and be between 8-15 characters", 'reg_pw')
        #regex explaination for future projects:
        # (?=.*[a-z])        // use positive look ahead to see if at least one lower case letter exists
        # (?=.*[A-Z])        // use positive look ahead to see if at least one upper case letter exists
        # (?=.*\d)           // use positive look ahead to see if at least one digit exists
        # (?=.*\W])        // use positive look ahead to see if at least one non-word character exists
    if request.form['confirm_password'] != request.form['password']:
        is_valid = False
        flash("Passwords must match", 'reg_pw_conf')

    if not is_valid:
    #need a session to return the form values to the form and autopopulate the inputs
    #Session stays until the user successfully registers, then once that happens they are directed to destroy_session and then to successful registration
        session['submitted'] = {
            "fname" : request.form['first_name'],
            "lname" : request.form['last_name'],
            "email" : request.form['email'],
        }
        print("*"*50, "\nSession values: ", session['submitted'])
        return redirect('/')
    else:

        #********** if all form data is validated, FIRST:  double check if user email already in the database. ************#
        #if there is actually a user
        mysql = connectToMySQL('login_reg_db')
        query = "SELECT * FROM users WHERE email = %(e)s;"
        data = {
            "e" : request.form["email"],
        }
        result = mysql.query_db(query, data)
        if len(result) == 0:           
            #hash password
            pw_hash = bcrypt.generate_password_hash(request.form['password'])
            #create session for "Success" page.  Create "logged in" session to follow user
            session['user'] = { 
                "logged_in" : True,
                "fname" : request.form['first_name']
            }
            user = session['user']
            #once data is validated - insert it into the DB
            query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(fnm)s, %(lnm)s, %(e)s, %(pw)s);"
        
            data = {
                "fnm" : request.form["first_name"],
                "lnm" : request.form["last_name"],
                "e" : request.form["email"],
                "pw" : pw_hash
            }
            mysql = connectToMySQL('login_reg_db')
            print(mysql.query_db(query, data))
            flash("You have been successfully registered!", 'success')
            return render_template("success.html", user = user)

        else:  # if there is a record, it will not result in zero
            flash("There is already an existing user by that email in the database", "reg_email")
            session['submitted'] = {
                "fname" : request.form['first_name'],
                "lname" : request.form['last_name'],
                "email" : request.form['email']
            }
            print("*"*50, "\nSession values: ", session['submitted'])
            return redirect('/')


@app.route("/login-verification", methods=['POST'])
def verify_logged_in_email():
    is_valid = True
    if not EMAIL_REGEX.match(request.form['login_email']):    # test whether a field matches the pattern
        is_valid = False
        flash("Invalid email address!", 'login_email')
    if not bool(re.match('^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])', request.form['login_password'])) or len(request.form['login_password']) > 14 or len(request.form['login_password']) < 7:
        is_valid = False
        # print(bool(re.match('^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])', request.form['password'])), request.form['password'])
        flash("Invalid password!", 'login_pw')


    if not is_valid:
    #need a session to return the form values to the form and autopopulate the inputs
    #Session stays until the user successfully registers, then once that happens they are directed to destroy_session and then to successful registration
        session['submitted'] = {
            "login_email" : request.form['login_email'],
        }
        return redirect('/')
    else:
        mysql = connectToMySQL('login_reg_db')
        query = "SELECT * FROM users WHERE email = %(e)s;"
        data = {
            "e" : request.form["login_email"],
        }
        result = mysql.query_db(query, data)
        print(result)
        if len(result) > 0:
            if bcrypt.check_password_hash(result[0]['password'], request.form['login_password']):
                session['user'] = { 
                    "logged_in" : True,
                    "userid" : result[0]['id'],
                    "fname" : result[0]['first_name']
                }
                user = session['user']
                print(user)
                return render_template("success.html", user = user)
        else:
            flash("You could not be logged in", 'login')
    return redirect('/') 


@app.route('/destroy_session')
def destroy_session_registration():
    session.clear()
    return redirect('/')











if __name__ == "__main__":
    app.run(debug=True)
