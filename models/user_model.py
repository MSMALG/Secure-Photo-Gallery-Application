from models import db
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError, Regexp

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key = True)  
    username = db.Column(db.String(20), nullable = False, unique = True)
    email = db.Column(db.String(120), nullable=False, unique=True)  
    password = db.Column(db.String(80), nullable = False)

class RegistrationForm(FlaskForm):
    username = StringField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})
    email = StringField(validators=[InputRequired(), Length(max=120)], render_kw={"placeholder": "Email"})
    password = PasswordField(validators=[
        InputRequired(),
        Length(min=8, max=20, message="Password must be 8-20 characters"),
        Regexp(r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z])',
               message="Must contain uppercase, lowercase, and numbers")
    ], render_kw={"placeholder": "Password"})    
    submit = SubmitField("Register")

    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError("Username already exists.")

    def validate_email(self, email):
        existing_email = User.query.filter_by(email=email.data).first()
        if existing_email:
            raise ValidationError("Email already in use.")

class LoginForm(FlaskForm):
    identifier = StringField(validators=[InputRequired(), Length(min=4, max=120)], render_kw={"placeholder": "Username or Email"})
    password = PasswordField(validators=[InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Password"})
    submit = SubmitField("Login")
    
