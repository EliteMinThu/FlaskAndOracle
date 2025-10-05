# =============================================================================
# SECTION 1: IMPORTS (လိုအပ်သော Werkzeug များ စုစည်းခြင်း)
# =============================================================================
import oracledb
from flask import Flask, request, jsonify
from flask_cors import CORS
import bcrypt
import uuid
import secrets
from datetime import datetime, timedelta
from flask_mail import Mail, Message
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

# =============================================================================
# SECTION 2: APP CONFIGURATION (App ကို ပြင်ဆင်ခြင်း)
# =============================================================================
app = Flask(__name__)
CORS(app)

# --- အရေးကြီး: ဒီနေရာမှာ သင့်ရဲ့ ကိုယ်ပိုင် KEY တွေကို ဖြည့်ပါ ---
GOOGLE_CLIENT_ID = "749824701715-rbude5i5p8qj0g35vdctmjkb3ea45n1i.apps.googleusercontent.com" 

# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'your_gmail_address@gmail.com'
app.config['MAIL_PASSWORD'] = 'your_16_digit_app_password' 
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

# Oracle DB Configuration (သင့်ရဲ့ အချက်အလက်များဖြင့် ဖြည့်ထားပါသည်)
ORACLE_USER = "ca"
ORACLE_PASSWORD = "pro"
ORACLE_DSN = "localhost:1521/orcl"

# oracledb connection pool
# Server စတင်ချိန်တွင် Database နှင့် ချိတ်ဆက်ရန် ကြိုးစားပါမည်
try:
    # --- FIXED: "encoding" argument ကို ဖြုတ်လိုက်ပါသည် ---
    pool = oracledb.create_pool(user=ORACLE_USER, password=ORACLE_PASSWORD, dsn=ORACLE_DSN, min=2, max=5, increment=1)
    print(">>> Database connection pool created successfully!")
except Exception as e:
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("!!! DATABASE CONNECTION POOL FAILED TO CREATE !!!")
    print("Error:", e)
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    pool = None

# --- Helper Functions (အထောက်အကူပြု Function များ) ---
def get_db_connection():
    if pool:
        return pool.acquire()
    else:
        # pool မရှိပါက error ပစ်ပါ
        raise Exception("Database pool is not available.")

def release_db_connection(connection):
    if pool:
        pool.release(connection)

def make_dict_factory(cursor):
    column_names = [d[0].lower() for d in cursor.description]
    def create_row(*args):
        return dict(zip(column_names, args))
    return create_row

# =============================================================================
# SECTION 3: ROUTES (လမ်းကြောင်းများ သတ်မှတ်ခြင်း)
# =============================================================================

@app.route('/')
def home():
    return "API for login/register is running with Oracle DB!"

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data['username']
    email = data['email']
    password = data['password'].encode('utf-8')
    
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE username = :username OR email = :email", username=username, email=email)
        if cursor.fetchone():
            return jsonify({'message': 'Username or email already exists'}), 409

        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())
        cursor.execute(
            "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)",
            username=username, email=email, password=hashed_password.decode('utf-8')
        )
        connection.commit()
        return jsonify({'message': 'User registered successfully!'})
    finally:
        cursor.close()
        release_db_connection(connection)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data['email']
    password = data['password'].encode('utf-8')

    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE email = :email", email=email)
        cursor.rowfactory = make_dict_factory(cursor)
        user = cursor.fetchone()
        
        if user and bcrypt.checkpw(password, user['password'].encode('utf-8')):
            return jsonify({'message': 'Login successful!', 'username': user['username']})
        else:
            return jsonify({'message': 'Invalid email or password'}), 401
    finally:
        cursor.close()
        release_db_connection(connection)

@app.route('/google-login', methods=['POST'])
def google_login():
    data = request.get_json()
    token = data['credential']
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        idinfo = id_token.verify_oauth2_token(token, google_requests.Request(), GOOGLE_CLIENT_ID)
        email = idinfo['email']
        username = idinfo.get('name', email.split('@')[0])
        
        cursor.execute("SELECT * FROM users WHERE email = :email", email=email)
        if not cursor.fetchone():
            random_password = str(uuid.uuid4()).encode('utf-8')
            hashed_password = bcrypt.hashpw(random_password, bcrypt.gensalt())
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)",
                username=username, email=email, password=hashed_password.decode('utf-8')
            )
            connection.commit()
        
        return jsonify({'message': 'Google login successful!', 'username': username})
    except ValueError:
        return jsonify({'message': 'Invalid Google token'}), 401
    finally:
        cursor.close()
        release_db_connection(connection)

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data['email']
    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE email = :email", email=email)
        if not cursor.fetchone():
            return jsonify({'message': 'If an account with that email exists, a password reset link has been sent.'})

        token = secrets.token_urlsafe(32)
        expiry = datetime.utcnow() + timedelta(hours=1)
        
        cursor.execute("UPDATE users SET reset_token = :token, reset_token_expiration = :expiry WHERE email = :email",
                       token=token, expiry=expiry, email=email)
        connection.commit()
        
        reset_url = f"http://localhost:5173/reset-password/{token}"
        msg = Message("Password Reset Request", sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f"To reset your password, please click the following link: {reset_url}"
        mail.send(msg)
        return jsonify({'message': 'If an account with that email exists, a password reset link has been sent.'})
    except Exception as e:
        print(str(e))
        return jsonify({'message': 'Could not send email. Please try again later.'}), 500
    finally:
        cursor.close()
        release_db_connection(connection)

@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data['token']
    new_password = data['password'].encode('utf-8')

    connection = get_db_connection()
    cursor = connection.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE reset_token = :token", token=token)
        cursor.rowfactory = make_dict_factory(cursor)
        user = cursor.fetchone()

        if not user or user['reset_token_expiration'].replace(tzinfo=None) < datetime.utcnow():
            return jsonify({'message': 'Invalid or expired token.'}), 400
            
        hashed_password = bcrypt.hashpw(new_password, bcrypt.gensalt())
        cursor.execute(
            "UPDATE users SET password = :password, reset_token = NULL, reset_token_expiration = NULL WHERE id = :id",
            password=hashed_password.decode('utf-8'), id=user['id']
        )
        connection.commit()
        return jsonify({'message': 'Password has been reset successfully.'})
    finally:
        cursor.close()
        release_db_connection(connection)

# =============================================================================
# SECTION 4: RUNNING THE APP (App ကို စတင် အလုပ်လုပ်စေခြင်း)
# =============================================================================
if __name__ == '__main__':
    app.run(debug=True)

