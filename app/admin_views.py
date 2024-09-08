from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask import redirect, url_for, request
from flask_login import current_user
from app import db
from app.models import User, Domain, Mailbox

# Create a custom ModelView to restrict admin access
class AdminModelView(ModelView):
    def is_accessible(self):
        # Only allow access if the user is authenticated and has a specific email (admin)
        return current_user.is_authenticated and current_user.email == "mjcbeckett@gmail.com"

    def inaccessible_callback(self, name, **kwargs):
        # Redirect to login page if the user is not authorized
        return redirect(url_for('auth.login', next=request.url))

# Initialize Admin
def init_admin(app):
    admin = Admin(app, name='MassMailbox Admin', template_mode='bootstrap4')

    # Add views for each model with unique names and endpoints to avoid conflicts
    admin.add_view(AdminModelView(User, db.session, name="User Admin", endpoint="admin_user"))
    admin.add_view(AdminModelView(Domain, db.session, name="Domain Admin", endpoint="admin_domain"))
    admin.add_view(AdminModelView(Mailbox, db.session, name="Mailbox Admin", endpoint="admin_mailbox"))

    return admin