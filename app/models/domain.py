from app import db

class Domain(db.Model):
    __tablename__ = 'domain'

    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(255), nullable=False)
    cloudflare_zone_id = db.Column(db.String(100), nullable=False)
    forwarding_url = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    # New field to track if the domain has been added to the server
    added_to_server = db.Column(db.Boolean, default=False, nullable=False)

    # Relationship to the Mailbox model
    mailboxes = db.relationship('Mailbox', backref='domain', lazy=True)

    def __repr__(self):
        return f'<Domain {self.domain}>'
