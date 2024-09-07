from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config.from_object('config')  # Load configuration from 'config.py'

    db.init_app(app)
    login_manager.init_app(app)

    login_manager.login_view = 'main.login'  # Set the login view
    login_manager.login_message_category = 'info'  # Optional: for flash messages

    from app.views import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app

# User loader function for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from app.models import User
    return User.query.get(int(user_id))
