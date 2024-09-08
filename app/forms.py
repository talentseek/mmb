from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, IntegerField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, URL, NumberRange

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

# Form for settings page
class SettingsForm(FlaskForm):
    cloudflare_email = StringField('Cloudflare Email', validators=[DataRequired(), Email()])
    cloudflare_api_key = StringField('Cloudflare API Key', validators=[DataRequired()])
    smartlead_api_key = StringField('Smartlead API Key', validators=[DataRequired()])
    submit = SubmitField('Save Settings')

# Form for adding domains
class DomainForm(FlaskForm):
    domain = StringField('Domain', validators=[DataRequired()])
    cloudflare_zone_id = StringField('Cloudflare Zone ID', validators=[DataRequired()])
    forwarding_url = StringField('Forwarding URL', validators=[DataRequired(), URL(message='Please enter a valid URL')])
    submit = SubmitField('Add Domain')

# Updated form for adding mailboxes
class MailboxForm(FlaskForm):
    domain_id = SelectField('Select Domain', coerce=int, validators=[DataRequired()])  # Populated from existing domains
    username = StringField('Username (left part of the email address)', validators=[DataRequired()])  # Replace Mailbox name and email format
    
    email_signature = TextAreaField('Email Signature (customizable, supports HTML)', validators=[DataRequired()])  # Allow HTML input
    
    message_per_day = IntegerField('Messages Per Day', default=40, validators=[DataRequired(), NumberRange(min=1, max=100)])
    minimum_time_gap = IntegerField('Minimum Time Gap (in minutes)', default=15, validators=[DataRequired(), NumberRange(min=1)])
    
    total_warmup_per_day = IntegerField('Total Warmup Emails Per Day', default=40, validators=[DataRequired(), NumberRange(min=1, max=100)])
    daily_rampup = IntegerField('Daily Rampup', default=5, validators=[DataRequired(), NumberRange(min=1, max=100)])
    reply_rate_percentage = IntegerField('Reply Rate Percentage', default=45, validators=[DataRequired(), NumberRange(min=0, max=100)])

    submit = SubmitField('Add Mailbox')