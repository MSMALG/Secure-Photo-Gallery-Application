#Getting users from database for testing purposes
from app import app  
from models.user_model import User  

with app.app_context():
    users = User.query.all()  
    if users:
        for user in users:
            print(f"Username: {user.username}, Email: {user.email}")
    else:
        print("No users found in the database.")
