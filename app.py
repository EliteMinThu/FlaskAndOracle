from flask import Flask, jsonify, request
from flask_mysqldb import MySQL
from flask_cors import CORS
import bcrypt
import uuid # Used for generating random passwords for Google users
# --- : Flask-Mail Imports ---
from flask_mail import Mail, Message
# --------------------------------

# --- Google Auth Imports ---
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
# --------------------------------

app = Flask(__name__)
CORS(app)

# --- Add your Google Client ID here ---
# It's better to store this in an environment variable, but for now, we'll put it here.
GOOGLE_CLIENT_ID = "749824701715-rbude5i5p8qj0g35vdctmjkb3ea45n1i.apps.googleusercontent.com"
# --------------------------------------------

# --- Flask-Mail Configuration ---
# For security, it's best to set these as environment variables
# For now, we will set them directly for learning purposes.
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'thureinforex@gmail.com' #
app.config['MAIL_PASSWORD'] = 'nnkk qrts bgxk ezns' # 
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)
# -----------------------------------
# MySQL Configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '007minthu' 
app.config['MYSQL_DB'] = 'flask_react_auth'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

@app.route('/')
def home():
    return "API for login/register is running!"

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password'].encode('utf-8')

    cursor = mysql.connection.cursor()
    
    # Check if user already exists
    cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
    existing_user = cursor.fetchone()
    
    if existing_user:
        return jsonify({'message': 'Username or email already exists'}), 409

    hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
    
    cursor.execute(
        "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
        (username, email, hashed_password)
    )
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({'message': 'User registered successfully!'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password'].encode('utf-8')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", [email])
    user = cursor.fetchone()
    cursor.close()

    if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
        return jsonify({'message': 'Login successful!', 'username': user['username']})
    else:
        return jsonify({'message': 'Invalid email or password'}), 401

# --- : Google Login Route ---
@app.route('/google-login', methods=['POST'])
def google_login():
    data = request.get_json()
    token = data['credential'] # The token sent from React frontend

    try:
        # Verify the token with Google
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        
        email = idinfo['email']
        username = idinfo.get('name', email.split('@')[0]) # Use name, or create username from email
        
        cursor = mysql.connection.cursor()
        
        # Check if this Google user already exists in our database
        cursor.execute("SELECT * FROM users WHERE email = %s", [email])
        user = cursor.fetchone()
        
        if not user:
            # If user doesn't exist, create a  one
            # We create a random password because they will not use it
            random_password = str(uuid.uuid4()).encode('utf-8')
            hashed_password = bcrypt.hashpw(random_password, bcrypt.gensalt())
            
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                (username, email, hashed_password)
            )
            mysql.connection.commit()

        cursor.close()
        
        # Login is successful, return username
        return jsonify({'message': 'Google login successful!', 'username': username})

    except ValueError:
        # Invalid token
        return jsonify({'message': 'Invalid Google token'}), 401
# ------------------------------------

# --- : Forgot Password Route ---
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data['email']
    
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE email = %s", [email])
    user = cursor.fetchone()
    
    if not user:
        # For security, don't reveal if the user exists or not
        return jsonify({'message': 'If an account with that email exists, a password reset link has been sent.'})

    # Generate a secure token
    token = secrets.token_urlsafe(32)
    # Token expiry time (e.g., 1 hour from now)
    expiry = datetime.utcnow() + timedelta(hours=1)
    
    # Store token and expiry in the database (we need to add these columns first!)
    # cursor.execute("UPDATE users SET reset_token = %s, reset_token_expiry = %s WHERE email = %s", (token, expiry, email))
    # mysql.connection.commit()
    
    # Send the email
    reset_url = f"http://localhost:5173/reset-password/{token}"
    msg = Message("Password Reset Request",
                  sender=app.config['MAIL_USERNAME'],
                  recipients=[email])
    msg.body = f"To reset your password, please click the following link: {reset_url}\n\nIf you did not make this request, please ignore this email."
    
    try:
        mail.send(msg)
        return jsonify({'message': 'If an account with that email exists, a password reset link has been sent.'})
    except Exception as e:
        # Log the error for debugging
        print(str(e))
        return jsonify({'message': 'Could not send email. Please try again later.'}), 500
    finally:
        cursor.close()
# ------------------------------------
# --- : Reset Password Route ---
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data['token']
    new_password = data['password'].encode('utf-8')

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM users WHERE reset_token = %s", [token])
    user = cursor.fetchone()

    if not user:
        return jsonify({'message': 'Invalid or expired token.'}), 400

    # Check if the token has expired
    if user['reset_token_expiration'] < datetime.utcnow():
        return jsonify({'message': 'Invalid or expired token.'}), 400
        
    # Hash the new password and update the database
    hashed_password = bcrypt.hashpw(new_password, bcrypt.gensalt())
    cursor.execute(
        "UPDATE users SET password = %s, reset_token = NULL, reset_token_expiration = NULL WHERE id = %s",
        (hashed_password, user['id'])
    )
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({'message': 'Password has been reset successfully.'})
# ------------------------------------

if __name__ == '__main__':
    app.run(debug=True)

