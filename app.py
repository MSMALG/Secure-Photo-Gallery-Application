from flask import Flask, render_template, request, redirect, send_from_directory, url_for, flash, abort
from config import Config
from models import db
from models.image_model import File
from models.user_model import User, RegistrationForm, LoginForm
from flask_login import login_manager, login_user, login_required, logout_user, current_user, LoginManager
from flask_bcrypt import Bcrypt
import os
from werkzeug.utils import secure_filename
from flask_mail import Mail, Message
from flask_mail import Message
from flask_migrate import Migrate

#AES encryption implementation 
from Crypto.Cipher import AES       
from Crypto.Protocol.KDF import PBKDF2  #This is or secure key derivation
from Crypto.Util.Padding import pad, unpad  #Handling data padding
from Crypto.Random import get_random_bytes  #Secure random number generator 


app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)  
migrate = Migrate(app, db)  
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

mail = Mail(app)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def welcome():
    return render_template('welcome.html')

@app.route('/gallery', methods = ['GET', 'POST'])
@login_required
def gallery():
    files = File.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', files=files)
    
@app.route('/uploads', methods = ['POST'])
@login_required
def uploads():
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file selected', 400
            
        file = request.files['file']
        if file.filename == '':
            return 'No selected file', 400
            
        if file and allowed_file(file.filename):
            #Creating user-specific directory
            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{current_user.id}')
            os.makedirs(user_folder, exist_ok=True)
            
            #Secure filename and save
            filename = secure_filename(file.filename)
            file_path = os.path.join(user_folder, filename)
            file.save(file_path)
            
            #Add to database the created user's folder 
            new_file = File(filename=filename, user_id=current_user.id)
            db.session.add(new_file)
            db.session.commit()
            
            return redirect(url_for('gallery'))
            
    return 'Invalid file type', 400


@app.route('/uploaded_file/<filename>')
@login_required
def uploaded_file(filename):
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{current_user.id}')
    return send_from_directory(user_folder, filename)
    #return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/delete/<int:file_id>')
@login_required
def delete(file_id):
    file = File.query.get_or_404(file_id)

    if file.user_id != current_user.id:
        return 'Unauthorized', 403
    
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{current_user.id}')
    file_path = os.path.join(user_folder, file.filename)
    
    if os.path.exists(file_path):
        os.remove(file_path)
    
    db.session.delete(file)
    db.session.commit()
    return redirect(url_for('gallery'))

@app.route('/delete_encrypted/<int:file_id>', methods=['POST'])
@login_required
def delete_encrypted(file_id):
    file = File.query.get_or_404(file_id)
    
    if file.user_id != current_user.id:
        abort(403)
    
    password = request.form.get('password')
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{current_user.id}')
    file_path = os.path.join(user_folder, file.filename)
    
    try:
        #Attempting decryption to verify the password 
        with open(file_path, 'rb') as f:
            data = f.read()
        
        salt = data[:16]
        iv = data[16:32]
        key = PBKDF2(password, salt, dkLen=32, count=100000)
        
        #Test decryption with first block
        cipher = AES.new(key, AES.MODE_CBC, iv)
        cipher.decrypt(data[32:48])  
        
    except Exception as e:
        flash('Invalid password for deletion', 'danger')
        return redirect(url_for('gallery'))
    
    #If password is verified, then proceed with deletion
    if os.path.exists(file_path):
        os.remove(file_path)
    
    db.session.delete(file)
    db.session.commit()
    flash('File deleted successfully', 'success')
    return redirect(url_for('gallery'))

@app.route('/login', methods = ['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        identifier = form.identifier.data
        user = User.query.filter((User.username == identifier) | (User.email == identifier)).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('gallery'))
        else:
                flash('Invalid credentials', 'danger')

    return render_template('login.html', form = form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            #Hashing password
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(username=form.username.data, email=form.email.data, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()

            #Create user-specific folder
            user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{new_user.id}')
            os.makedirs(user_folder, exist_ok=True)

            #Send confirmation email
            msg = Message("Account Confirmation", recipients=[new_user.email])
            msg.html = f"""<h1>Thank you for joining, {new_user.username}!</h1>
            <p>Click <a href='{url_for('login', _external=True)}'>here</a> to activate your account.</p>"""

            try:
                mail.send(msg)
            except Exception as e:
                app.logger.error(f"Failed to send email: {str(e)}")
                flash('Account created, but failed to send confirmation email.', 'warning')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            app.logger.error(f"Registration error: {str(e)}")
            flash('Registration failed. Please try again.', 'danger')
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{getattr(form, field).label.text}: {error}", 'danger')
    return render_template('register.html', form=form)

@app.route('/logout', methods = ['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('welcome'))

#ENCRYPTION 
@app.route('/encrypt/<int:file_id>', methods=['POST'])
@login_required
def encrypt_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)
    
    #Getting password from form
    password = request.form.get('password')
    
    #Getting the File path
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{current_user.id}')
    file_path = os.path.join(user_folder, file.filename)
    
    #Generate random salt (16 bytes) and IV (16 bytes)
    salt = get_random_bytes(16)
    iv = get_random_bytes(16)
    
    #Key derivation (PBKDF2 with 100,000 iterations)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    
    #Read file as binary and encrypt file
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    
    #Save salt + iv + ciphertext
    with open(file_path, 'wb') as f:
        f.write(salt + iv + ciphertext)
    
    # pdate database
    file.is_encrypted = True
    db.session.commit()

    flash('File encrypted successfully', 'success')
    return redirect(url_for('gallery'))


#DECRYPTION
@app.route('/decrypt/<int:file_id>', methods=['POST'])
@login_required
def decrypt_file(file_id):
    file = File.query.get_or_404(file_id)
    if file.user_id != current_user.id:
        abort(403)
    
    password = request.form.get('password')
    
    user_folder = os.path.join(app.config['UPLOAD_FOLDER'], f'user_{current_user.id}')
    file_path = os.path.join(user_folder, file.filename)
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    #Extract components used in key derivation 
    salt = data[:16]
    iv = data[16:32]
    ciphertext = data[32:]
    
    #Re-derive key
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    
    try:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    except (ValueError, KeyError):
        flash('Decryption failed - wrong password?', 'danger')
        return redirect(url_for('gallery'))
    
    #Save decrypted file by writing on it
    with open(file_path, 'wb') as f:
        f.write(plaintext)
    
    file.is_encrypted = False
    db.session.commit()
    
    flash('File decrypted successfully', 'success')
    return redirect(url_for('gallery'))


if __name__ == '__main__':
    app.run()
