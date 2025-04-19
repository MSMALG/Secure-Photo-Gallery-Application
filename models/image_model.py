from flask_sqlalchemy import SQLAlchemy
from models import db



class File(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    filename = db.Column(db.String(200), nullable = False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    user = db.relationship('User', backref='files') 
    is_encrypted = db.Column(db.Boolean, default=False)   #encryption status  


