import os
import shutil
from app import app  # Import your Flask app
from models.user_model import User, db  # Import the User model and the db object

# Define the path to the upload folder (this should match your actual config)
UPLOAD_FOLDER = app.config['UPLOAD_FOLDER']  # Assuming this is where user images are stored

# Open the app context
with app.app_context():
    # Query all users to get their IDs and associated folders
    users = User.query.all()

    for user in users:
        # Delete user's associated folder and files if it exists
        user_folder = os.path.join(UPLOAD_FOLDER, f'user_{user.id}')
        if os.path.exists(user_folder):
            shutil.rmtree(user_folder)  # Remove the entire folder and its contents

    # Delete all users from the database
    db.session.query(User).delete()
    db.session.commit()  # Commit the changes to the database

    print("All users and their files have been deleted.")
