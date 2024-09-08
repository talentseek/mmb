import time
import requests
from flask import Blueprint, render_template, redirect, url_for, flash
from flask_login import login_required, current_user
from app.models import Domain
from app.forms import DomainForm
from app import db

domain = Blueprint('domain', __name__)

# Log errors
def log_error(message):
    print(f"Error: {message}")

# Add domain to Mailcow
def add_domain_to_mailcow(domain):
    """Add domain to Mailcow instance."""
    MAILCOW_API_ENDPOINT = "https://mail.trycpd.com/api/v1/"
    MAILCOW_API_KEY = "2035F6-3A8156-CCB4CD-58FCCF-D22BF8"
    
    url = f"{MAILCOW_API_ENDPOINT}add/domain"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": MAILCOW_API_KEY
    }
    data = {
        "domain": domain,
        "description": f"Domain for {domain}",
        "aliases": "400",
        "mailboxes": "10",
        "defquota": "3072",
        "maxquota": "10240",
        "quota": "10240",
        "active": "1",
        "rl_value": "500",
        "rl_frame": "s",
        "backupmx": "0",
        "relay_all_recipients": "0",
        "restart_sogo": "10",
        "tags": []
    }
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        print(f"Domain {domain} added to Mailcow successfully.")
        return True
    except requests.exceptions.RequestException as e:
        log_error(f"Failed to add domain {domain} to Mailcow: {e}")
        return False

# Retrieve DKIM key from Mailcow
def get_dkim_key(domain):
    """Retrieve the DKIM key for the specified domain from Mailcow."""
    MAILCOW_API_ENDPOINT = "https://mail.trycpd.com/api/v1/"
    MAILCOW_API_KEY = "2035F6-3A8156-CCB4CD-58FCCF-D22BF8"

    url = f"{MAILCOW_API_ENDPOINT}get/dkim/{domain}"
    headers = {
        "Content-Type": "application/json",
        "X-API-Key": MAILCOW_API_KEY
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        dkim_data = response.json()
        print(f"DKIM Key for {domain} retrieved successfully.")
        return dkim_data
    except requests.exceptions.RequestException as e:
        log_error(f"Failed to retrieve DKIM key for {domain}: {e}")
        return None

# Clear DNS records in Cloudflare
def clear_cloudflare_records(zone_id):
    """Clear all existing DNS records in Cloudflare for the specified zone ID."""
    CLOUDFLARE_API_EMAIL = current_user.cloudflare_email
    CLOUDFLARE_API_KEY = current_user.cloudflare_api_key

    headers = {
        "X-Auth-Email": CLOUDFLARE_API_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API_KEY,
        "Content-Type": "application/json"
    }
    try:
        dns_records_response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", headers=headers)
        dns_records_response.raise_for_status()

        dns_records = dns_records_response.json().get("result", [])
        for record in dns_records:
            delete_response = requests.delete(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record['id']}", headers=headers)
            delete_response.raise_for_status()
        
        print(f"All DNS records cleared for zone ID {zone_id}.")
        return True
    except requests.exceptions.RequestException as e:
        log_error(f"Failed to clear DNS records for zone ID {zone_id}: {e}")
        return False

# Add DNS records to Cloudflare
def add_dns_records_to_cloudflare(domain, zone_id, dkim_txt_record):
    """Add necessary DNS records for the domain to Cloudflare."""
    CLOUDFLARE_API_EMAIL = current_user.cloudflare_email
    CLOUDFLARE_API_KEY = current_user.cloudflare_api_key

    headers = {
        "X-Auth-Email": CLOUDFLARE_API_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API_KEY,
        "Content-Type": "application/json"
    }

    MAIL_SERVER_IPv4 = "89.117.48.239"
    MAIL_SERVER_IPv6 = "2a02:c206:2154:7659::1"

    dns_records = [
        {"type": "TXT", "name": "@", "content": f"v=spf1 ip4:{MAIL_SERVER_IPv4} ip6:{MAIL_SERVER_IPv6} ~all"},
        {"type": "TXT", "name": "dkim._domainkey", "content": dkim_txt_record},
        {"type": "MX", "name": "@", "content": "mail.trycpd.com", "priority": 10},
        {"type": "CNAME", "name": "autoconfig", "content": "mail.trycpd.com"},
        {"type": "CNAME", "name": "autodiscover", "content": "mail.trycpd.com"},
        {"type": "A", "name": "mail", "content": MAIL_SERVER_IPv4},
        {"type": "AAAA", "name": "mail", "content": MAIL_SERVER_IPv6},
        {"type": "TXT", "name": "_dmarc", "content": f"v=DMARC1; p=reject; rua=mailto:dmarc-reports@{domain}; ruf=mailto:dmarc-failures@{domain}; fo=1"},
        {"type": "A", "name": "@", "content": "54.149.79.189", "proxied": True}
    ]

    for record in dns_records:
        data = {
            "type": record["type"],
            "name": record["name"],
            "content": record["content"],
            "priority": record.get("priority", 0),
            "proxied": record.get("proxied", False)
        }
        try:
            response = requests.post(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records", headers=headers, json=data)
            response.raise_for_status()
            print(f"DNS record {record['type']} for {record['name']} added successfully.")
        except requests.exceptions.RequestException as e:
            log_error(f"Failed to add DNS record {record['type']} for {record['name']}: {e}")
            return False

    return True

# Delete existing page rules in Cloudflare
def delete_existing_page_rules(zone_id):
    """Delete existing page rules in Cloudflare for the given zone."""
    CLOUDFLARE_API_EMAIL = current_user.cloudflare_email
    CLOUDFLARE_API_KEY = current_user.cloudflare_api_key

    headers = {
        "X-Auth-Email": CLOUDFLARE_API_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API_KEY
    }

    try:
        response = requests.get(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/pagerules", headers=headers)
        response.raise_for_status()
        page_rules = response.json().get("result", [])

        for rule in page_rules:
            rule_id = rule['id']
            delete_response = requests.delete(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/pagerules/{rule_id}", headers=headers)
            delete_response.raise_for_status()
            print(f"Deleted page rule {rule_id} for {rule['targets'][0]['constraint']['value']}")

        return True
    except requests.exceptions.RequestException as e:
        log_error(f"Failed to delete page rules: {e}")
        return False

# Add forwarding rule to Cloudflare
def add_forwarding_rule(zone_id, domain, forwarding_url):
    """Create a forwarding rule in Cloudflare."""
    CLOUDFLARE_API_EMAIL = current_user.cloudflare_email
    CLOUDFLARE_API_KEY = current_user.cloudflare_api_key

    headers = {
        "X-Auth-Email": CLOUDFLARE_API_EMAIL,
        "X-Auth-Key": CLOUDFLARE_API_KEY,
        "Content-Type": "application/json"
    }

    data = {
        "targets": [{
            "target": "url",
            "constraint": {
                "operator": "matches",
                "value": f"{domain}/*"
            }
        }],
        "actions": [{
            "id": "forwarding_url",
            "value": {
                "url": forwarding_url,
                "status_code": 301
            }
        }],
        "priority": 1,
        "status": "active"
    }

    try:
        response = requests.post(f"https://api.cloudflare.com/client/v4/zones/{zone_id}/pagerules", headers=headers, json=data)
        response.raise_for_status()
        print(f"Forwarding rule for {domain} added successfully.")
        return True
    except requests.exceptions.RequestException as e:
        log_error(f"Failed to create forwarding rule for {domain}: {e}")
        return False

# Route to manage domains
@domain.route('/domains', methods=['GET', 'POST'])
@login_required
def manage_domains():
    form = DomainForm()

    if form.validate_on_submit():
        # Step 1: Add domain to Mailcow
        print(f"Starting process for adding domain {form.domain.data} to Mailcow.")
        if add_domain_to_mailcow(form.domain.data):
            print(f"Domain {form.domain.data} added to Mailcow. Proceeding to DNS configuration.")
            
            # Step 2: Retrieve DKIM key after waiting
            time.sleep(5)
            dkim_data = get_dkim_key(form.domain.data)
            if not dkim_data:
                flash('Failed to retrieve DKIM key.', 'danger')
                return redirect(url_for('domain.manage_domains'))

            dkim_txt_record = dkim_data.get('dkim_txt', 'Not Available')
            print(f"DKIM key retrieved: {dkim_txt_record}")

            # Step 3: Clear existing DNS records in Cloudflare
            print(f"Clearing existing DNS records in Cloudflare for domain {form.domain.data}.")
            if clear_cloudflare_records(form.cloudflare_zone_id.data):
                
                # Step 4: Add DNS records to Cloudflare
                print(f"Adding DNS records for domain {form.domain.data}.")
                if add_dns_records_to_cloudflare(form.domain.data, form.cloudflare_zone_id.data, dkim_txt_record):
                    print(f"DNS records for {form.domain.data} added successfully.")
                    
                    # Step 5: Delete existing page rules in Cloudflare
                    print(f"Deleting existing page rules for domain {form.domain.data}.")
                    if delete_existing_page_rules(form.cloudflare_zone_id.data):
                        
                        # Step 6: Add forwarding rule to Cloudflare
                        print(f"Adding forwarding rule for domain {form.domain.data}.")
                        if add_forwarding_rule(form.cloudflare_zone_id.data, form.domain.data, form.forwarding_url.data):
                            print(f"Forwarding rule for {form.domain.data} added successfully.")
                            
                            # Save the domain to the database after successful DNS and forwarding rule configuration
                            new_domain = Domain(
                                user_id=current_user.id,
                                domain=form.domain.data,
                                cloudflare_zone_id=form.cloudflare_zone_id.data,
                                forwarding_url=form.forwarding_url.data,
                                added_to_server=True
                            )
                            db.session.add(new_domain)
                            db.session.commit()

                            flash('Domain added successfully with DNS and forwarding rule!', 'success')
                        else:
                            flash('Failed to create forwarding rule in Cloudflare.', 'danger')
                            print(f"Failed to add forwarding rule for domain {form.domain.data}.")
                    else:
                        flash('Failed to delete existing page rules in Cloudflare.', 'danger')
                        print(f"Failed to delete existing page rules for domain {form.domain.data}.")
                else:
                    flash('Failed to set DNS records in Cloudflare.', 'danger')
                    print(f"Failed to set DNS records for domain {form.domain.data}.")
            else:
                flash('Failed to clear DNS records in Cloudflare.', 'danger')
                print(f"Failed to clear DNS records for domain {form.domain.data}.")
        else:
            flash('Failed to add domain to Mailcow.', 'danger')
            print(f"Failed to add domain {form.domain.data} to Mailcow.")

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