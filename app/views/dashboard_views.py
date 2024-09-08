from flask import Blueprint, render_template, redirect, url_for, flash, request, current_app
from flask_login import login_required, current_user
from app.forms import SettingsForm
from app import db
import stripe

dashboard = Blueprint('dashboard', __name__)

@dashboard.route('/dashboard')
@login_required
def dashboard_view():
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

# Add a route for the settings page
@dashboard.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = SettingsForm()

    if form.validate_on_submit():
        current_user.cloudflare_email = form.cloudflare_email.data
        current_user.cloudflare_api_key = form.cloudflare_api_key.data
        current_user.smartlead_api_key = form.smartlead_api_key.data
        db.session.commit()
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('dashboard.settings'))

    if request.method == 'GET':
        form.cloudflare_email.data = current_user.cloudflare_email
        form.cloudflare_api_key.data = current_user.cloudflare_api_key
        form.smartlead_api_key.data = current_user.smartlead_api_key

    return render_template('settings.html', form=form)

# Add a route for billing
@dashboard.route('/billing')
@login_required
def billing():
    stripe.api_key = current_app.config['STRIPE_SECRET_KEY']

    # Check if the user has a Stripe customer ID
    if not current_user.stripe_customer_id:
        flash('No Stripe customer ID found. Please subscribe to a plan first.', 'danger')
        return redirect(url_for('dashboard.dashboard_view'))

    try:
        session = stripe.billing_portal.Session.create(
            customer=current_user.stripe_customer_id,
            return_url=url_for('dashboard.dashboard_view', _external=True),
        )
        return redirect(session.url)
    except stripe.error.InvalidRequestError as e:
        flash(f"Error: {e.user_message}", 'danger')
        return redirect(url_for('dashboard.dashboard_view'))

# Add a route for checkout
@dashboard.route('/checkout/<plan_id>')
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
        success_url=url_for('dashboard.subscription_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
        cancel_url=url_for('dashboard.dashboard_view', _external=True),
    )
    return redirect(session.url)

# Add a route for successful subscription
@dashboard.route('/subscription_success')
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
    return redirect(url_for('dashboard.dashboard_view'))