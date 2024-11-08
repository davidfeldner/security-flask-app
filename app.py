import json, sqlite3, click, functools, os, hashlib,time, random, sys, bcrypt
from flask import Flask, current_app, g, session, redirect, render_template, url_for, request
from datetime import timedelta
from secrets import token_urlsafe

def validate_password(password):
    errors = []
    
    if len(password) < 12:
        errors.append("Password must be at least 12 characters long")
    
    if not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one number")
    
    if not any(c in "!@#$%^&*" for c in password):
        errors.append("Password must contain at least one special character (!@#$%^&*)")
    
    # Return tuple of (is_valid, error_messages)
    return (len(errors) == 0, errors)

### DATABASE FUNCTIONS ###

def connect_db():
    return sqlite3.connect(app.database)

def init_db():
    """Initializes the database with our great SQL schema"""
    conn = connect_db()
    db = conn.cursor()
    db.executescript("""

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS notes;

CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assocUser INTEGER NOT NULL,
    dateWritten DATETIME NOT NULL,
    note TEXT NOT NULL,
    publicID INTEGER NOT NULL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    salt TEXT NOT NULL
);

INSERT INTO users VALUES(null,"a", "password","whatever");
INSERT INTO users VALUES(null,"b", "omgMPC", "whatever2");
INSERT INTO notes VALUES(null,2,"1993-09-23 10:10:10","hello my friend",1234567890);
INSERT INTO notes VALUES(null,2,"1993-09-23 12:10:10","i want lunch pls",1234567891);

""")



### APPLICATION SETUP ###
app = Flask(__name__)
app.database = "db.sqlite3"
app.secret_key = token_urlsafe(32)
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
    SESSION_PERMANENT=True,
    SESSION_COOKIE_SECURE=True,  # Only send cookie over HTTPS
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access to session cookie
    SESSION_COOKIE_SAMESITE='Lax'  # Protect against CSRF
)
#print(bcrypt.hashpw("password", "whatever"))
#print(bcrypt.hashpw("omgMPC", "whatever2"))

### ADMINISTRATOR'S PANEL ###
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

@app.route("/")
def index():
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        return redirect(url_for('notes'))


@app.route("/notes/", methods=('GET', 'POST'))
@login_required
def notes():
    importerror=""
    #Posting a new note:
    if request.method == 'POST':
        if request.form['submit_button'] == 'add note':
            note = request.form['noteinput']
            db = connect_db()
            c = db.cursor()
            statement = "INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null,?,?,?,?);"
            print(statement)
            c.execute(statement, (session['userid'],time.strftime('%Y-%m-%d %H:%M:%S'),note,random.randrange(1, 10000)))
            db.commit()
            db.close()
        elif request.form['submit_button'] == 'import note':
            noteid = request.form['noteid']
            db = connect_db()
            c = db.cursor()
            statement = """SELECT * from NOTES where publicID = %s""" %noteid
            c.execute(statement)
            result = c.fetchall()
            if(len(result)>0):
                row = result[0]
                statement = "INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null,?,?,?,?);"
                c.execute(statement, (session['userid'],row[2],row[3],row[4]))
            else:
                importerror="No such note with that ID!"
            db.commit()
            db.close()
    
    db = connect_db()
    c = db.cursor()
    statement = "SELECT * FROM notes WHERE assocUser = ?;" 
    print(statement)
    c.execute(statement, (session['userid'],))
    notes = c.fetchall()
    print(notes)
    
    return render_template('notes.html',notes=notes,importerror=importerror)


@app.route("/login/", methods=('GET', 'POST'))
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        try:
            db = connect_db()
            c = db.cursor()

            Statement = "SELECT * FROM users WHERE username = ?"
            c.execute(Statement, (username,))
            result = c.fetchall()
            
            if len(result) == 1:
                stored_hash = result[0][2]  # The stored hashed password
                
                # Directly compare the password with stored hash
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                    session.clear()
                    session.permanent = True
                    session['logged_in'] = True
                    session['userid'] = result[0][0]
                    session['username'] = result[0][1]

                    session['created_at'] = time.time()
                    session['ip_address'] = request.remote_addr
                    session['user_agent'] = request.user_agent.string

                    return redirect(url_for('index'))
                else:
                    error = "Wrong username or password!"
            else:
                error = "Wrong username or password!"
        except Exception as e:
            # Log the error securely, don't expose details to user
            app.logger.error(f"Login error: {str(e)}")
            error = "An error occurred during login"
        finally:
            if 'db' in locals():
                db.close()
            
    return render_template('login.html', error=error)


@app.route("/register/", methods=('GET', 'POST'))
def register():
    errored = False
    usererror = ""
    passworderror = ""
    if request.method == 'POST':
        

        username = request.form['username']
        password = request.form['password']

        # Validate password
        is_valid, password_errors = validate_password(password)
        if not is_valid:
            return render_template('register.html', 
                                usererror="",
                                passworderror=password_errors)
        db = connect_db()
        c = db.cursor()

        user_statement = "SELECT * FROM users WHERE username = ?;"


        c.execute(user_statement, (username,))
        result = c.fetchall()
        if len(result) > 0:
            errored = True
            usererror = "That username is already in use by someone else!"
 

        if(not errored):
            salt = bcrypt.gensalt()
            hashedPassword = bcrypt.hashpw(password.encode('utf-8'), salt)

            statement = "INSERT INTO users(id,username,password) VALUES(null,?,?);" 
            print(statement)
            c.execute(statement, (username, hashedPassword))
            db.commit()
            db.close()
            return f"""<html>
                        <head>
                            <meta http-equiv="refresh" content="2;url=/" />
                        </head>
                        <body>
                            <h1>SUCCESS!!! Redirecting in 2 seconds...</h1>
                        </body>
                        </html>
                        """
        
        db.commit()
        db.close()
    return render_template('register.html',usererror=usererror,passworderror=passworderror)

@app.route("/logout/")
@login_required
def logout():
    """Logout: clears the session"""
    session.clear()
    return redirect(url_for('index'))

if __name__ == "__main__":
    #create database if it doesn't exist yet
    if not os.path.exists(app.database):
        init_db()
    runport = 5000
    if(len(sys.argv)==2):
        runport = sys.argv[1]
    try:
        app.run(host='0.0.0.0', port=runport) # runs on machine ip address to make it visible on netowrk
    except:
        print("Something went wrong. the usage of the server is either")
        print("'python3 app.py' (to start on port 5000)")
        print("or")
        print("'sudo python3 app.py 80' (to run on any other port)")

