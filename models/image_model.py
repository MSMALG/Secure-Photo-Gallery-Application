from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class File(db.Model):
    id = db.Column(db.Integer, primary_key = True)
    filename = db.Column(db.String(200), nullable = False)


