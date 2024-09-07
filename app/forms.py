from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    first_name = StringField('First Name', validators=[DataRequired()])
    last_name = StringField('Last Name', validators=[DataRequired()])
    submit = SubmitField('Sign Up')

# New form for settings page
class SettingsForm(FlaskForm):
    cloudflare_email = StringField('Cloudflare Email', validators=[DataRequired(), Email()])
    cloudflare_api_key = StringField('Cloudflare API Key', validators=[DataRequired()])
    smartlead_api_key = StringField('Smartlead API Key', validators=[DataRequired()])
    submit = SubmitField('Save Settings')
