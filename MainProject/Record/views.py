from flask import render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from flask_bcrypt import Bcrypt
from Record import app
import requests
import sqlite3

def login_table():
    conn = sqlite3.connect('login.db')
    cursor = conn.cursor()


    cursor.execute('''
    CREATE TABLE IF NOT EXISTS login (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL,
        password TEXT NOT NULL
    );
    ''')
    conn.commit()

def students_table():
    conn = sqlite3.connect('students.db')
    cursor = conn.cursor()


    cursor.execute('''
    CREATE TABLE IF NOT EXISTS students (
        name TEXT NOT NULL,
        addr TEXT NOT NULL,
        city TEXT NOT NULL
    );
    ''')
    conn.commit()
    
login_table()
students_table()

bcrypt = Bcrypt(app)

app.config['SECRET_KEY'] = 'thisIsSecret'
login_manager = LoginManager(app)
login_manager.login_view = "login"


@app.route('/')
def home():
    if current_user.is_authenticated:
        return render_template('home.html')
    else:
        return redirect(url_for('login'))

@app.route('/enternew')
@login_required
def new_student():
    return render_template('student.html')

@app.route('/addrec', methods=['POST', 'GET'])
@login_required
def addrec():
    if request.method == 'POST':
        try:
            name = request.form['name']
            addr = request.form['add']
            city = request.form['city']
            
            with sqlite3.connect("students.db") as con:
                cur = con.cursor()
                cur.execute("INSERT INTO students (name, addr, city) VALUES (?, ?, ?)", (name, addr, city))
                con.commit()
                msg = "Record successfully added"
        except:
            con.rollback()
            msg = "Error in insert operation"
        finally:
            con.close()
        
        return render_template("result.html", msg=msg)

@app.route('/liststudents')
@login_required
def listStudents():
    con = sqlite3.connect("students.db")
    con.row_factory = sqlite3.Row
    cur = con.cursor()
    cur.execute("SELECT * FROM students")
    rows = cur.fetchall()
    return render_template("studentlist.html", rows=rows)

@app.route('/login')
def login():
    return render_template('login.html')

class User(UserMixin):
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password
        self.authenticated = False

    def is_active(self):
        return True

    def is_anonymous(self):
        return False

    def is_authenticated(self):
        return self.authenticated

    def get_id(self):
        return self.id

@app.route('/login', methods=['POST'])
def login_post():
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    con = sqlite3.connect("login.db")
    curs = con.cursor()
    email = request.form['email']
    curs.execute("SELECT * FROM login WHERE email = (?)", [email])

    row = curs.fetchone()
    if row is None:
        flash('Please try logging in again')
        return render_template('login.html')

    user = list(row)
    liUser = User(int(user[0]), user[1], user[2])
    password = request.form['password']

    match = bcrypt.check_password_hash(liUser.password, password)

    if match and email == liUser.email:
        login_user(liUser, remember=request.form.get('remember'))
        return redirect(url_for('home'))
    else:
        flash('Please try logging in again')
        return render_template('login.html')

    return render_template('home.html')

@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect('login.db')
    curs = conn.cursor()
    curs.execute("SELECT * FROM login WHERE user_id = (?)", [user_id])
    
    liUser = curs.fetchone()
    if liUser is None:
        return None
    else:
        return User(int(liUser[0]), liUser[1], liUser[2])

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    # Check if the user is already authenticated/logged in
    if current_user.is_authenticated:
        return redirect(url_for('home'))

    # Standard database operations
    con = sqlite3.connect("login.db")
    curs = con.cursor()
    
    email = request.form['email']
    password = request.form['password']
    
    # Hash the password using bcrypt with salt
    hashedPassword = bcrypt.generate_password_hash(password)

    # Insert the hashed password into the database
    con.execute('INSERT INTO login (email, password) VALUES (?, ?)', [email, hashedPassword])
    con.commit()
    
    return render_template('home.html')

