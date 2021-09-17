from flask_app import app
from flask import render_template,redirect,request, session
from flask_app.models.user import User
from flask import flash
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt(app)

@app.route('/login_register')
def load_home_page():
    return render_template('login_register.html')

@app.route('/register', methods=['POST'])
def register_user():
    if (request.form['pass_ent'] != request.form['pass_con']):
        flash('Passwords do not match!')
        return redirect('/login_register')
    if (len(request.form['pass_ent']) < 8):
        flash('Password is not long enough!')
        return redirect('/login_register')
    else:
        pw_hash = bcrypt.generate_password_hash(request.form['pass_ent'])
        print(pw_hash)
    
    data = {
        'fname' : request.form['fname'],
        'lname' : request.form['lname'],
        'email' : request.form['email'],
        'password' : pw_hash
    }

    if not User.validate_email_reg(data):
        return redirect('/login_register')
    User.register_user(data)
    user_in_db = User.get_by_email(data)
    session['user_id'] = user_in_db.id
    session['user'] = user_in_db.first_name
    return redirect('/reg_success')

@app.route('/reg_success')
def reg_success():
    if 'user' in session:
        user = session['user']
    return render_template('/reg_success.html', user = user)


@app.route('/login', methods=['POST'])
def login():
    data = {'email' : request.form['email_log']}
    user_in_db = User.get_by_email(data)
    print(user_in_db)

    if not user_in_db:
        flash('Invalid Email/Password')
        return redirect('/login_register')

    elif not bcrypt.check_password_hash(user_in_db.password, request.form['pass_log']):
        flash ('Invalid Email/Password')
        return redirect('/login_register')

    session['user_id'] = user_in_db.id
    session['user_name'] = user_in_db.first_name
    return redirect('/dashboard')


@app.route('/dashboard')
def render_dashboard():
    if 'user_id' not in session:
        return redirect('/logout')
    user = session['user_name']
    user_id = session['user_id']
    return render_template('dashboard.html', user= user, user_id = user_id)



@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login_register')
