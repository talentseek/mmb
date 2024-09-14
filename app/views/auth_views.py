from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_user, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from app.models.user import User #changed for new file structure 
from app.forms import LoginForm, RegisterForm
from app import db
import stripe
from flask import current_app

auth = Blueprint('auth', __name__)

# Route to the home page
@auth.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.dashboard_view'))
    return render_template('main.html')

# Route to login page
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard.dashboard_view'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard.dashboard_view'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html', form=form)

# Route to signup page
@auth.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(email=form.email.data, password=hashed_password, first_name=form.first_name.data, last_name=form.last_name.data)
        
        stripe.api_key = current_app.config['STRIPE_SECRET_KEY']
        customer = stripe.Customer.create(email=form.email.data)
        new_user.stripe_customer_id = customer.id
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('You have successfully registered!', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('signup.html', form=form)

# Route to handle user logout
@auth.route('/logout')
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('auth.login'))