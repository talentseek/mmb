import stripe
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_admin import Admin

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()  # Initialize CSRF protection
admin = Admin(template_mode='bootstrap4')  # Initialize Flask-Admin with bootstrap4 for consistency

def create_app():
    app = Flask(__name__, template_folder='templates')
    app.config.from_object('config')

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'  # Update the login view to auth

    # Set Stripe API key within the application context
    with app.app_context():
        stripe.api_key = app.config['STRIPE_SECRET_KEY']

    # Initialize Migrate with app and database
    migrate.init_app(app, db)

    # Initialize CSRF protection
    csrf.init_app(app)

    # Register Blueprints
    from app.views.auth_views import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    from app.views.dashboard_views import dashboard as dashboard_blueprint
    app.register_blueprint(dashboard_blueprint)

    from app.views.domain_views import domain as domain_blueprint
    app.register_blueprint(domain_blueprint)

    from app.views.mailbox_views import mailbox as mailbox_blueprint
    app.register_blueprint(mailbox_blueprint)

    # Initialize Flask-Admin
    from app.admin_views import init_admin
    init_admin(app)  # Call the function to set up admin with models

    return app

@login_manager.user_loader
def load_user(user_id):
    from app.models.user import User
    return User.query.get(int(user_id))
