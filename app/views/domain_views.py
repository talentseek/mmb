from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import Domain
from app.forms import DomainForm
from app import db

domain = Blueprint('domain', __name__)

# Route to manage domains
@domain.route('/domains', methods=['GET', 'POST'])
@login_required
def manage_domains():
    form = DomainForm()
    
    if form.validate_on_submit():
        new_domain = Domain(
            user_id=current_user.id,
            domain=form.domain.data,
            cloudflare_zone_id=form.cloudflare_zone_id.data,
            forwarding_url=form.forwarding_url.data
        )
        db.session.add(new_domain)
        db.session.commit()

        flash('Domain added successfully!', 'success')
        return redirect(url_for('domain.manage_domains'))

    user_domains = Domain.query.filter_by(user_id=current_user.id).all()
    return render_template('domains.html', form=form, domains=user_domains)

# Route to delete a domain
@domain.route('/delete_domain/<int:domain_id>', methods=['POST'])
@login_required
def delete_domain(domain_id):
    domain = Domain.query.get_or_404(domain_id)

    if domain.user_id != current_user.id:
        flash('You are not authorized to delete this domain.', 'danger')
        return redirect(url_for('domain.manage_domains'))

    db.session.delete(domain)
    db.session.commit()
    flash('Domain deleted successfully!', 'success')
    return redirect(url_for('domain.manage_domains'))