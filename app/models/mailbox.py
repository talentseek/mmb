from app import db

class Mailbox(db.Model):
    __tablename__ = 'mailbox'

    id = db.Column(db.Integer, primary_key=True)
    email_address = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)  # Full name field
    password = db.Column(db.String(255), nullable=False)  # Password field
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey('domain.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.now())
    email_signature = db.Column(db.Text, nullable=False)
    message_per_day = db.Column(db.Integer, default=40)
    minimum_time_gap = db.Column(db.Integer, default=15)
    total_warmup_per_day = db.Column(db.Integer, default=40)
    daily_rampup = db.Column(db.Integer, default=5)
    reply_rate_percentage = db.Column(db.Integer, default=45)
    
    # New status flags
    added_to_server = db.Column(db.Boolean, default=False, nullable=False)
    added_to_smartlead = db.Column(db.Boolean, default=False, nullable=False)
    
    def __repr__(self):
        return f'<Mailbox {self.email_address}>'
