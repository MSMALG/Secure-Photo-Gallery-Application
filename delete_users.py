#Deleting users from database for testing purposes
import os
import shutil
from app import app  #Importing Flask app
from models.user_model import User, db  #Importing the User model and the db object

UPLOAD_FOLDER = app.config['UPLOAD_FOLDER']  

with app.app_context():
    users = User.query.all()

    for user in users:
        # Delete user's associated folder and files if it exists
        user_folder = os.path.join(UPLOAD_FOLDER, f'user_{user.id}')
        if os.path.exists(user_folder):
            shutil.rmtree(user_folder)  # Remove the entire folder and its contents

    db.session.query(User).delete()
    db.session.commit()  

    print("All users and their files have been deleted.")
