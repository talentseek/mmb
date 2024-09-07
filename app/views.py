from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from app.models import User
from app.forms import LoginForm, RegisterForm

main = Blueprint('main', __name__)

# Home route
@main.route('/')
def index():
    return render_template('main.html')

# Login route
@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        
        if user:
            print(f"User found: {user.email}")
        else:
            print("No user found with that email.")
        
        if user and check_password_hash(user.password, form.password.data):
            print("Password matches!")
            login_user(user)
            return redirect(url_for('main.dashboard'))
        else:
            print("Invalid email or password.")
            flash('Invalid email or password', 'danger')

    return render_template('login.html', form=form)

# Signup route
@main.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(email=form.email.data, password=hashed_password, 
                        first_name=form.first_name.data, last_name=form.last_name.data)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('main.login'))

    return render_template('signup.html', form=form)

# Dashboard route (only accessible to logged-in users)
@main.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

# Logout route
@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.index'))
