# =============================================================================
# SECTION 1: IMPORTS (လိုအပ်သော Werkzeug များ စုစည်းခြင်း)
# =============================================================================
import oracledb # Oracle Database နဲ့ ချိတ်ဆက်ဖို့၊ အချက်အလက်တွေ ထည့်/ဖတ်/ပြင်/ဖျက် လုပ်ဖို့အတွက် အဓိကသုံးတဲ့ library ပါ။
from flask import Flask, request, jsonify
from flask_cors import CORS #Frontend (ဥပမာ React app) နဲ့ Backend (ဒီ Flask app) ကြားမှာ data အပြန်အလှန် လက်ခံလို့ရအောင် ခွင့်ပြုပေးတဲ့ security feature တစ်ခုပါ။
import bcrypt
import uuid#ဒါတွေက ကျပန်း (random) ဖြစ်ပြီး ခန့်မှန်းလို့မရတဲ့ စာတန်းတွေထုတ်ပေးဖို့ပါ။ secrets ကို password reset token လို လုံခြုံရေးမြင့်တဲ့ နေရာတွေမှာသုံးပါတယ်။
import secrets
from datetime import datetime, timedelta #အချိန်နဲ့ ရက်စွဲတွေကို ကိုင်တွယ်ဖို့ပါ။ Password reset link ဘယ်အချိန်မှာ expire ဖြစ်မယ်ဆိုတာမျိုး သတ်မှတ်ဖို့ သုံးပါတယ်။ 
from flask_mail import Mail, Message # Password reset link တွေ ပို့ဖို့အတွက် email ပို့တဲ့ လုပ်ဆောင်ချက်ကို ကိုင်တွယ်ပေးပါတယ်။
from google.oauth2 import id_token # User က "Sign in with Google" ကို နှိပ်လိုက်ရင် Google ကနေ ပြန်ပို့ပေးလိုက်တဲ့ token က မှန်ကန်ရဲ့လားဆိုတာ စစ်ဆေးဖို့ Google ရဲ့ library တွေပါ။
from google.auth.transport import requests as google_requests
from flask import session #User တစ်ယောက် login ဝင်ပြီးသွားရင်၊ သူဘယ်သူလဲဆိုတာ မှတ်ထားဖို့ (logged-in state ကို ထိန်းသိမ်းဖို့) သုံးပါတယ်။

# =============================================================================
# SECTION 2: APP CONFIGURATION (App ကို ပြင်ဆင်ခြင်း)
# =============================================================================
app = Flask(__name__)
app.config['SESSION_COOKIE_SAMESITE'] = 'None'
app.config['SESSION_COOKIE_SECURE'] = True
CORS(
    app,
    supports_credentials=True,
    resources={r"/*": {"origins": ["http://localhost:5173", "http://127.0.0.1:5173"]}},
)
app.secret_key = 'minthuyein007'



# --- အရေးကြီး: ဒီနေရာမှာ ကိုယ်ပိုင် KEY တွေကို ဖြည့်ပါ ---
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
ORACLE_DSN = "localhost:1521/orcl" #data source name

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
            session['user_id'] = user['id'] 
            return jsonify({'message': 'Login successful!', 'username': user['username'], email: user['email']})
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
        # --- FIX: Dictionary အဖြစ်ပြောင်းဖို့ rowfactory ထည့်ပါ ---
        cursor.rowfactory = make_dict_factory(cursor)
        user = cursor.fetchone()
        
        # User မရှိသေးရင် အသစ်ဆောက်ပါ
        if not user:
            random_password = str(uuid.uuid4()).encode('utf-8')
            hashed_password = bcrypt.hashpw(random_password, bcrypt.gensalt())
            cursor.execute(
                "INSERT INTO users (username, email, password) VALUES (:username, :email, :password)",
                username=username, email=email, password=hashed_password.decode('utf-8')
            )
            connection.commit()
            # အသစ်ဆောက်ပြီး user ကို ပြန်ရှာပါ
            cursor.execute("SELECT * FROM users WHERE email = :email", email=email)
            cursor.rowfactory = make_dict_factory(cursor)
            user = cursor.fetchone()

        # ---> ✅ အရေးကြီး: Session ကို ဒီနေရာမှာ သတ်မှတ်ပေးရပါမယ် <---
        if user:
            session['user_id'] = user['id']
            return jsonify({'message': 'Google login successful!', 'username': user['username'], 'email': user['email']})
        else:
            return jsonify({'message': 'Failed to create or find user after Google auth.'}), 500

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


#cvform Routes
# app.py ထဲက /cvform route ကို ဒီอันနဲ့ အစားထိုးပါ

@app.route('/cvform', methods=['POST'])
def cvform():
    if 'user_id' not in session:
        return jsonify({'message': 'Authentication required. Please log in.'}), 401

    user_id = session['user_id']
    data = request.get_json()
    note_content = data.get('note')

    if not note_content:
        return jsonify({'message': 'Note content cannot be empty.'}), 400

    connection = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        # MERGE statement (Oracle's "upsert" command)
        # user_id ကို ရှာမယ်၊ တွေ့ရင် UPDATE၊ မတွေ့ရင် INSERT လုပ်မယ်
        cursor.execute("""
            MERGE INTO notes n
            USING (SELECT :user_id AS user_id FROM dual) src
            ON (n.user_id = src.user_id)
            WHEN MATCHED THEN
                UPDATE SET n.content = :content, n.updated_at = SYSTIMESTAMP
            WHEN NOT MATCHED THEN
                INSERT (user_id, title, content, created_at, updated_at)
                VALUES (:user_id, :title, :content, SYSTIMESTAMP, SYSTIMESTAMP)
        """, {
            'user_id': user_id,
            'content': note_content,
            'title': 'My Note' # title ကို လောလောဆယ် ဒီအတိုင်းထားနိုင်ပါတယ်
        })

        connection.commit()
        return jsonify({'message': 'Note saved successfully!'}), 201

    except Exception as e:
        print(f"Database Error: {e}")
        connection.rollback() # Error ဖြစ်ရင် rollback လုပ်ပါ
        return jsonify({'message': 'An error occurred while saving the note.'}), 500
    finally:
        if connection:
            cursor.close()
            release_db_connection(connection)

# -------------------------------------------------------------------------

# app.py ထဲက /get-latest-note route ကိုလည်း ဒီอันနဲ့ အစားထိုးပါ
# ပိုပြီး ရိုးရှင်းသွားပါမယ်

# app.py ထဲက ဒီ function ကို အောက်က code နဲ့ အစားထိုးပါ

@app.route('/get-latest-note', methods=['GET'])
def get_latest_note():
    if 'user_id' not in session:
        return jsonify({'message': 'Authentication required.'}), 401

    user_id = session['user_id']
    connection = None
    try:
        connection = get_db_connection()
        cursor = connection.cursor()
        
        cursor.execute(
            "SELECT content FROM notes WHERE user_id = :user_id",
            user_id=user_id
        )
        
        cursor.rowfactory = make_dict_factory(cursor)
        note = cursor.fetchone()
        
        # --- ဒီနေရာက အဓိက ပြင်ဆင်ချက်ပါ ---
        if note and note.get('content'):
            # LOB object ကို .read() နဲ့ ဖတ်ပြီး သာမန် string အဖြစ် ပြောင်းလဲလိုက်ပါတယ်
            note['content'] = note['content'].read()
            return jsonify(note)
        else:
            # Note မရှိရင် (သို့) content က အလွတ်ဖြစ်နေရင်
            return jsonify({'content': ''})

    except Exception as e:
        # Error တက်ရင် terminal မှာ print ထုတ်ပြီး frontend ကို error message ပို့ပါတယ်
        print(f"Database Error: {e}")
        return jsonify({'message': 'An error occurred while fetching the note.'}), 500
    finally:
        if connection:
            cursor.close()
            release_db_connection(connection)
        
@app.route('/test-session')
def test_session():
    return jsonify(dict(session))
# =============================================================================
# SECTION 4: RUNNING THE APP (App ကို စတင် အလုပ်လုပ်စေခြင်း)
# =============================================================================
if __name__ == '__main__':
    app.run(debug=True)

