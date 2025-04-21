#Testing if the confirmation email is sent. 
from flask import Flask
from flask_mail import Mail, Message
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

#Initializing Flask-Mail
mail = Mail(app)

@app.route('/test-email')
def test_email():
    try:
        msg = Message(
            "Test Email",
            recipients=["bdoor12123@gmail.com"],  
            body="This is a test email from Flask using Gmail SMTP with app password."
        )
        mail.send(msg)
        return "Test email sent!"
    except Exception as e:
        return f"Failed to send test email: {e}"

if __name__ == '__main__':
    app.run(debug=True)
