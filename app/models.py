from app import db
from flask_login import UserMixin

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    first_name = db.Column(db.String(150), nullable=False)
    last_name = db.Column(db.String(150), nullable=False)
    stripe_customer_id = db.Column(db.String(100), nullable=True)
    stripe_subscription_id = db.Column(db.String(100), nullable=True)
    stripe_plan_id = db.Column(db.String(100), nullable=True)
    subscription_status = db.Column(db.String(50), nullable=True)
    
    # Fields for Cloudflare and Smartlead API credentials
    cloudflare_email = db.Column(db.String(150), nullable=True)
    cloudflare_api_key = db.Column(db.String(100), nullable=True)
    smartlead_api_key = db.Column(db.String(100), nullable=True)
    
    # Relationships
    domains = db.relationship('Domain', backref='user', lazy=True)
    mailboxes = db.relationship('Mailbox', backref='user', lazy=True)

# Domain model
class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    cloudflare_zone_id = db.Column(db.String(100), nullable=False)
    forwarding_url = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key to User model

    # Relationship to the Mailbox model
    mailboxes = db.relationship('Mailbox', backref='domain', lazy=True)

    def __repr__(self):
        return f'<Domain {self.domain}>'

# Mailbox model (removed mailbox_type)
class Mailbox(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email_address = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Foreign key to User model
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)  # Foreign key to Domain model
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())  # Timestamp
    email_signature = db.Column(db.Text, nullable=False)
    message_per_day = db.Column(db.Integer, default=40)
    minimum_time_gap = db.Column(db.Integer, default=15)
    total_warmup_per_day = db.Column(db.Integer, default=40)
    daily_rampup = db.Column(db.Integer, default=5)
    reply_rate_percentage = db.Column(db.Integer, default=45)

    def __repr__(self):
        return f'<Mailbox {self.email_address}>'