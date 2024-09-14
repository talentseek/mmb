from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    __tablename__ = 'user'

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
