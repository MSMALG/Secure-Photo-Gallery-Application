from flask import Flask, render_template, request, redirect, send_from_directory, url_for
from flask_sqlalchemy import SQLAlchemy
from config import Config
from models.image_model import db, File
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
#from models.user_model import User
from flask_bcrypt import Bcrypt
import os

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

with app.app_context():
    db.create_all()

@app.route('/')
def index():
    files = File.query.all()
    return render_template('index.html', files = files)

@app.route('/uploads', methods = ['POST'])
def uploads():
    if request.method == 'POST':
       file = request.files['file']
       if file:
           filename = file.filename
           file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
           new_file = File(filename = filename)
           db.session.add(new_file)
           db.session.commit()
           return redirect('/')
    return 'Something went wrong. Please Try again.'

@app.route('/uploaded_file/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/download/<int:file_id>')
def download(file_id):
    file = File.query.get_or_404(file_id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename, as_attachment = True)

@app.route('/delete/<int:file_id>')
def delete(file_id):
    file = File.query.get_or_404(file_id)
    filename = file.filename
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    os.remove(file_path)
    db.session.delete(file)
    db.session.commit()
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
