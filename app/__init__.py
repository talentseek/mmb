import stripe
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect

db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()  # Initialize CSRF protection

def create_app():
    app = Flask(__name__, template_folder='templates')
    app.config.from_object('config')

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'main.login'

    # Set Stripe API key within the application context
    with app.app_context():
        stripe.api_key = app.config['STRIPE_SECRET_KEY']

    # Initialize Migrate with app and database
    migrate.init_app(app, db)

    # Initialize CSRF protection
    csrf.init_app(app)

    # Register Blueprints
    from app.views import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app

@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))
