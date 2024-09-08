from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app, jsonify
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from app.models import User, Domain, Mailbox  # Added Mailbox model
from app.forms import LoginForm, RegisterForm, SettingsForm, DomainForm, MailboxForm  # Import MailboxForm
import stripe

# Define the blueprint for the main app
main = Blueprint('main', __name__)

# Route to the home page
@main.route('/')
def index():
    return render_template('main.html')

# Route to login page
@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('main.dashboard'))
        else:
            flash('Invalid email or password', 'danger')
    
    return render_template('login.html', form=form)

# Route to signup page
@main.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')
        new_user = User(email=form.email.data, password=hashed_password, first_name=form.first_name.data, last_name=form.last_name.data)
        
        # Create a Stripe customer for the user within the app context
        stripe.api_key = current_app.config['STRIPE_SECRET_KEY']
        customer = stripe.Customer.create(email=form.email.data)
        new_user.stripe_customer_id = customer.id
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('You have successfully registered!', 'success')
        return redirect(url_for('main.login'))
    
    return render_template('signup.html', form=form)

# Route to the user dashboard
@main.route('/dashboard')
@login_required
def dashboard():
    stripe_basic_plan_id = current_app.config['STRIPE_BASIC_PLAN_ID']
    stripe_pro_plan_id = current_app.config['STRIPE_PRO_PLAN_ID']
    stripe_expert_plan_id = current_app.config['STRIPE_EXPERT_PLAN_ID']

    plan_names = {
        stripe_basic_plan_id: 'Basic',
        stripe_pro_plan_id: 'Pro',
        stripe_expert_plan_id: 'Expert'
    }

    plan_name = plan_names.get(current_user.stripe_plan_id, 'Unknown Plan')

    # Check if Cloudflare and Smartlead credentials exist
    missing_credentials = not (current_user.cloudflare_email and current_user.cloudflare_api_key and current_user.smartlead_api_key)

    return render_template(
        'dashboard.html', 
        stripe_basic_plan_id=stripe_basic_plan_id, 
        stripe_pro_plan_id=stripe_pro_plan_id, 
        stripe_expert_plan_id=stripe_expert_plan_id,
        plan_name=plan_name,
        missing_credentials=missing_credentials
    )

# Route to the settings page
@main.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = SettingsForm()
    
    if form.validate_on_submit():
        # Save Cloudflare and Smartlead API credentials
        current_user.cloudflare_email = form.cloudflare_email.data
        current_user.cloudflare_api_key = form.cloudflare_api_key.data
        current_user.smartlead_api_key = form.smartlead_api_key.data
        db.session.commit()
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('main.settings'))

    # Prepopulate form with the existing user data if available
    if request.method == 'GET':
        form.cloudflare_email.data = current_user.cloudflare_email
        form.cloudflare_api_key.data = current_user.cloudflare_api_key
        form.smartlead_api_key.data = current_user.smartlead_api_key

    return render_template('settings.html', form=form)

# Route to handle user logout
@main.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('main.login'))

# Route to handle Stripe subscription management
@main.route('/billing')
@login_required
def billing():
    stripe.api_key = current_app.config['STRIPE_SECRET_KEY']
    
    if not current_user.stripe_customer_id:
        flash('No Stripe customer ID found. Please subscribe to a plan first.', 'danger')
        return redirect(url_for('main.dashboard'))

    try:
        session = stripe.billing_portal.Session.create(
            customer=current_user.stripe_customer_id,
            return_url=url_for('main.dashboard', _external=True),
        )
        return redirect(session.url)
    except stripe.error.InvalidRequestError as e:
        flash(f"Error: {e.user_message}", 'danger')
        return redirect(url_for('main.dashboard'))

# Route to handle Stripe subscription checkout
@main.route('/checkout/<plan_id>')
@login_required
def checkout(plan_id):
    stripe.api_key = current_app.config['STRIPE_SECRET_KEY']
    session = stripe.checkout.Session.create(
        payment_method_types=['card'],
        line_items=[{
            'price': plan_id,
            'quantity': 1,
        }],
        mode='subscription',
        customer_email=current_user.email,
        success_url=url_for('main.subscription_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
        cancel_url=url_for('main.dashboard', _external=True),
    )
    return redirect(session.url)

# Route to handle successful subscription
@main.route('/subscription_success')
@login_required
def subscription_success():
    stripe.api_key = current_app.config['STRIPE_SECRET_KEY']
    session_id = request.args.get('session_id')
    
    # Retrieve the Stripe checkout session and subscription details
    checkout_session = stripe.checkout.Session.retrieve(session_id, expand=['subscription', 'line_items'])
    subscription = checkout_session.subscription
    line_items = checkout_session.line_items.data
    price_id = line_items[0].price.id if line_items else None
    
    # Update user's subscription details in the database
    current_user.stripe_subscription_id = subscription.id if subscription else None
    current_user.stripe_plan_id = price_id
    current_user.subscription_status = 'active'
    
    db.session.commit()
    
    flash('Subscription successful!', 'success')
    return redirect(url_for('main.dashboard'))

# Route to manage domains
@main.route('/domains', methods=['GET', 'POST'])
@login_required
def domains():
    form = DomainForm()
    
    if form.validate_on_submit():
        # Save the domain to the database
        new_domain = Domain(
            user_id=current_user.id,
            domain=form.domain.data,
            cloudflare_zone_id=form.cloudflare_zone_id.data,
            forwarding_url=form.forwarding_url.data
        )
        db.session.add(new_domain)
        db.session.commit()

        flash('Domain added successfully!', 'success')
        return redirect(url_for('main.domains'))

    user_domains = Domain.query.filter_by(user_id=current_user.id).all()
    return render_template('domains.html', form=form, domains=user_domains)

# Route to delete a domain
@main.route('/delete_domain/<int:domain_id>', methods=['POST'])
@login_required
def delete_domain(domain_id):
    domain = Domain.query.get_or_404(domain_id)

    if domain.user_id != current_user.id:
        flash('You are not authorized to delete this domain.', 'danger')
        return redirect(url_for('main.domains'))

    db.session.delete(domain)
    db.session.commit()
    flash('Domain deleted successfully!', 'success')
    return redirect(url_for('main.domains'))

# Route to verify domain (MXToolbox)
@main.route('/verify_domain/<int:domain_id>')
@login_required
def verify_domain(domain_id):
    domain = Domain.query.get_or_404(domain_id)

    if domain.user_id != current_user.id:
        flash('You are not authorized to verify this domain.', 'danger')
        return redirect(url_for('main.domains'))

    verify_url = f"https://mxtoolbox.com/emailhealth/{domain.domain}"
    return redirect(verify_url)

# Route to manage mailboxes
@main.route('/mailboxes', methods=['GET', 'POST'])
@login_required
def mailboxes():
    form = MailboxForm()
    
    # Get the domains for the current user
    user_domains = Domain.query.filter_by(user_id=current_user.id).all()
    form.domain_id.choices = [(domain.id, domain.domain) for domain in user_domains]  # Populate domain choices in the form

    if form.validate_on_submit():
        # Construct the email format using the domain and username
        domain = Domain.query.get(form.domain_id.data)
        email_address = f"{form.username.data}@{domain.domain}"
        
        # Save the mailbox to the database
        new_mailbox = Mailbox(
            user_id=current_user.id,
            domain_id=form.domain_id.data,  # Associate mailbox with the selected domain
            email_address=email_address,  # Constructed email address
            email_signature=form.email_signature.data,
            message_per_day=form.message_per_day.data,
            minimum_time_gap=form.minimum_time_gap.data,
            total_warmup_per_day=form.total_warmup_per_day.data,
            daily_rampup=form.daily_rampup.data,
            reply_rate_percentage=form.reply_rate_percentage.data
        )
        db.session.add(new_mailbox)
        db.session.commit()

        flash('Mailbox added successfully!', 'success')
        return redirect(url_for('main.mailboxes'))

    # Fetch user's mailboxes to display
    user_mailboxes = Mailbox.query.filter_by(user_id=current_user.id).all()

    return render_template('mailboxes.html', form=form, domains=user_domains, mailboxes=user_mailboxes)

# Context processor for adding the navigation bar to every page
@main.app_context_processor
def inject_navigation():
    return dict(
        navigation=[
            {'name': 'Dashboard', 'url': url_for('main.dashboard')},
            {'name': 'Settings', 'url': url_for('main.settings')},
            {'name': 'Domains', 'url': url_for('main.domains')},
            {'name': 'Mailboxes', 'url': url_for('main.mailboxes')}
        ]
    )