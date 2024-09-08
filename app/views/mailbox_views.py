from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import Domain, Mailbox
from app.forms import MailboxForm
from app import db
import requests

mailbox = Blueprint('mailbox', __name__)

# Helper function to log errors
def log_error(message):
    print(f"Error: {message}")

# Function to add mailbox to Mailcow
def add_mailbox_to_mailcow(domain, username, full_name, password):
    MAILCOW_API_ENDPOINT = "https://mail.trycpd.com/api/v1/"
    MAILCOW_API_KEY = "2035F6-3A8156-CCB4CD-58FCCF-D22BF8"

    url = f"{MAILCOW_API_ENDPOINT}add/mailbox"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": MAILCOW_API_KEY
    }
    data = {
        "local_part": username,
        "domain": domain,
        "name": full_name,
        "password": password,  # User-defined password
        "password2": password,  # Repeat password for confirmation
        "quota": 10240,  # Set quota if needed
        "active": 1
    }
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        print(f"Mailbox {username}@{domain} added successfully to Mailcow.")
        return True
    except requests.exceptions.RequestException as e:
        log_error(f"Failed to add mailbox {username}@{domain} to Mailcow: {e}")
        return False

# Function to add mailbox to SmartLead
def add_mailbox_to_smartlead(email, full_name, domain, signature, message_per_day, total_warmup_per_day, daily_rampup, reply_rate_percentage, password):
    SMARTLEAD_API_KEY = current_user.smartlead_api_key  # SmartLead API key from user settings
    SMARTLEAD_API_ENDPOINT = f"https://server.smartlead.ai/api/v1/email-accounts/save?api_key={SMARTLEAD_API_KEY}"

    data = {
        "from_name": full_name,
        "from_email": email,
        "user_name": email,
        "password": password,  # User-defined password for SMTP/IMAP
        "smtp_host": f"mail.{domain}",
        "smtp_port": 587,
        "imap_host": f"mail.{domain}",
        "imap_port": 993,
        "max_email_per_day": message_per_day,
        "total_warmup_per_day": total_warmup_per_day,
        "daily_rampup": daily_rampup,
        "reply_rate_percentage": reply_rate_percentage,
        "signature": signature,
        "imap_user_name": email,
        "imap_password": password,  # Use the user-defined password
        "warmup_enabled": True
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    
    try:
        response = requests.post(SMARTLEAD_API_ENDPOINT, headers=headers, json=data)
        response.raise_for_status()
        print(f"Mailbox {email} added successfully to SmartLead.")
        return True
    except requests.exceptions.RequestException as e:
        log_error(f"Failed to add mailbox {email} to SmartLead: {e}")
        return False

# Route to manage mailboxes
@mailbox.route('/mailboxes', methods=['GET', 'POST'])
@login_required
def manage_mailboxes():
    form = MailboxForm()

    user_domains = Domain.query.filter_by(user_id=current_user.id).all()
    form.domain_id.choices = [(domain.id, domain.domain) for domain in user_domains]

    if form.validate_on_submit():
        domain = Domain.query.get(form.domain_id.data)
        email_address = f"{form.username.data}@{domain.domain}"
        
        # Add mailbox to Mailcow
        added_to_mailcow = add_mailbox_to_mailcow(domain.domain, form.username.data, form.full_name.data, form.password.data)
        added_to_smartlead = False

        if added_to_mailcow:
            # Add mailbox to SmartLead
            added_to_smartlead = add_mailbox_to_smartlead(
                email_address, 
                form.full_name.data, 
                domain.domain, 
                form.email_signature.data, 
                form.message_per_day.data, 
                form.total_warmup_per_day.data, 
                form.daily_rampup.data, 
                form.reply_rate_percentage.data,
                form.password.data  # Pass the user-defined password
            )
        
        # Save mailbox details to database after successful addition
        new_mailbox = Mailbox(
            user_id=current_user.id,
            domain_id=form.domain_id.data,
            email_address=email_address,
            full_name=form.full_name.data,  # Save full name
            password=form.password.data,  # Save user-defined password
            email_signature=form.email_signature.data,
            message_per_day=form.message_per_day.data,
            minimum_time_gap=form.minimum_time_gap.data,
            total_warmup_per_day=form.total_warmup_per_day.data,
            daily_rampup=form.daily_rampup.data,
            reply_rate_percentage=form.reply_rate_percentage.data,
            added_to_server=added_to_mailcow,
            added_to_smartlead=added_to_smartlead
        )
        db.session.add(new_mailbox)
        db.session.commit()

        if added_to_mailcow and added_to_smartlead:
            flash(f'Mailbox {email_address} added to both server and SmartLead!', 'success')
        elif added_to_mailcow:
            flash(f'Mailbox {email_address} added to Mailcow, but failed to add to SmartLead.', 'warning')
        else:
            flash(f'Failed to add mailbox {email_address} to Mailcow.', 'danger')

        return redirect(url_for('mailbox.manage_mailboxes'))

    user_mailboxes = Mailbox.query.filter_by(user_id=current_user.id).all()
    return render_template('mailboxes.html', form=form, domains=user_domains, mailboxes=user_mailboxes)

# Route to delete a mailbox
@mailbox.route('/delete_mailbox/<int:mailbox_id>', methods=['POST'])
@login_required
def delete_mailbox(mailbox_id):
    mailbox = Mailbox.query.get_or_404(mailbox_id)

    if mailbox.user_id != current_user.id:
        flash('You are not authorized to delete this mailbox.', 'danger')
        return redirect(url_for('mailbox.manage_mailboxes'))

    db.session.delete(mailbox)
    db.session.commit()
    flash('Mailbox deleted successfully!', 'success')
    return redirect(url_for('mailbox.manage_mailboxes'))