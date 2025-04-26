import os
from dotenv import load_dotenv

load_dotenv() 
BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(BASE_DIR, 'instance', 'database.db')  
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = 'static/uploads'
    SECRET_KEY = os.environ.get('SECRET_KEY', 'fallback-insecure-key-for-dev-only')
    UPLOAD_FOLDER = os.path.join('static', 'uploads') #'static/uploads' 
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER')





    
