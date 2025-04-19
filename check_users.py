from app import app  # Import your Flask app
from models.user_model import User  # Import the User model

# Open the app context
with app.app_context():
    users = User.query.all()  # Get all users
    if users:
        for user in users:
            print(f"Username: {user.username}, Email: {user.email}")
    else:
        print("No users found in the database.")
