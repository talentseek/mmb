from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import Domain, Mailbox
from app.forms import MailboxForm
from app import db

mailbox = Blueprint('mailbox', __name__)

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

        new_mailbox = Mailbox(
            user_id=current_user.id,
            domain_id=form.domain_id.data,
            email_address=email_address,
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