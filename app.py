import streamlit as st
import json
import os
import time
import base64
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import hashlib

# Set page configuration
st.set_page_config(
    page_title="Secure Data Vault",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="expanded"
)

# Add custom CSS for black theme
def apply_custom_css():
    st.markdown("""
    <style>
    .stApp {
        background-color: #121212;
        color: #FFFFFF;
    }
    .stButton button {
        background-color: #3D0066;
        color: white;
        border-radius: 5px;
        padding: 10px 24px;
        font-weight: bold;
        border: none;
        transition: all 0.3s;
    }
    .stButton button:hover {
        background-color: #6E00B3;
        box-shadow: 0 0 10px rgba(110, 0, 179, 0.5);
    }
    .special-box {
        background-color: #1E1E1E;
        border: 1px solid #333333;
        border-radius: 10px;
        padding: 20px;
        margin-bottom: 20px;
    }
    .title-box {
        text-align: center;
        padding: 10px;
        background: linear-gradient(90deg, #3D0066, #6E00B3);
        border-radius: 10px;
        margin-bottom: 20px;
    }
    .warning-text {
        color: #FF5252;
        font-weight: bold;
    }
    .success-text {
        color: #4CAF50;
        font-weight: bold;
    }
    .info-text {
        color: #2196F3;
        font-weight: bold;
    }
    input, textarea {
        background-color: #2D2D2D !important;
        color: #00FFFF !important; 
        border: 1px solid #444444 !important;
        border-radius: 5px !important;
    }
    /* Target specific input fields by their labels */
    [data-testid="stTextInput"] div[data-baseweb="input"] input[aria-label*="Username"] {
        color: #FF9900 !important;  /* Orange color for username */
    }
    [data-testid="stTextInput"] div[data-baseweb="input"] input[aria-label*="Password"] {
        color: #00FF00 !important;  /* Green color for password */
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #2D2D2D;
        border-radius: 4px 4px 0px 0px;
        padding: 10px 16px;
        color: white;
    }
    .stTabs [aria-selected="true"] {
        background-color: #3D0066 !important;
        color: white !important;
    }
    [data-testid="stSidebar"] {
        background-color: #1E1E1E;
    }
    </style>
    """, unsafe_allow_html=True)

apply_custom_css()

# Initialize session state variables
if 'auth_status' not in st.session_state:
    st.session_state.auth_status = False
if 'attempt_count' not in st.session_state:
    st.session_state.attempt_count = 0
if 'lockout_until' not in st.session_state:
    st.session_state.lockout_until = None
if 'data_store' not in st.session_state:
    st.session_state.data_store = {}
if 'current_page' not in st.session_state:
    st.session_state.current_page = "home"
if 'user' not in st.session_state:
    st.session_state.user = None

# File paths
DATA_FILE = "secure_data.json"
USER_FILE = "users.json"

# Load data from files
def load_data():
    try:
        if os.path.exists(DATA_FILE):
            with open(DATA_FILE, 'r') as file:
                st.session_state.data_store = json.load(file)
    except Exception as e:
        st.error(f"Error loading data: {e}")
        st.session_state.data_store = {}

def load_users():
    try:
        if os.path.exists(USER_FILE):
            with open(USER_FILE, 'r') as file:
                return json.load(file)
        return {}
    except Exception as e:
        st.error(f"Error loading users: {e}")
        return {}

# Save data to files
def save_data():
    try:
        with open(DATA_FILE, 'w') as file:
            json.dump(st.session_state.data_store, file)
    except Exception as e:
        st.error(f"Error saving data: {e}")

def save_users(users):
    try:
        with open(USER_FILE, 'w') as file:
            json.dump(users, file)
    except Exception as e:
        st.error(f"Error saving users: {e}")

# Security functions
def generate_key_from_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(passkey.encode()))
    return key, salt

def encrypt_data(data, passkey):
    key, salt = generate_key_from_passkey(passkey)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())
    return {
        'encrypted': base64.b64encode(encrypted_data).decode(),
        'salt': base64.b64encode(salt).decode(),
        'timestamp': datetime.now().isoformat()
    }

def decrypt_data(encrypted_info, passkey):
    try:
        salt = base64.b64decode(encrypted_info['salt'])
        key, _ = generate_key_from_passkey(passkey, salt)
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(base64.b64decode(encrypted_info['encrypted']))
        return decrypted_data.decode()
    except Exception:
        return None

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(32)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return base64.b64encode(hash_obj).decode(), base64.b64encode(salt).decode()

def verify_password(password, stored_hash, salt):
    salt = base64.b64decode(salt)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    computed_hash = base64.b64encode(hash_obj).decode()
    return computed_hash == stored_hash

# Navigation functions
def go_to_home():
    st.session_state.current_page = "home"

def go_to_store():
    st.session_state.current_page = "store"

def go_to_retrieve():
    st.session_state.current_page = "retrieve"

def go_to_login():
    st.session_state.current_page = "login"
    st.session_state.auth_status = False

def go_to_register():
    st.session_state.current_page = "register"

def check_lockout():
    if st.session_state.lockout_until and datetime.now() < st.session_state.lockout_until:
        remaining = st.session_state.lockout_until - datetime.now()
        minutes, seconds = divmod(remaining.seconds, 60)
        st.error(f"🔒 Account locked. Try again in {minutes}m {seconds}s")
        return True
    return False

# User authentication functions
def login_user(username, password):
    users = load_users()
    if username in users:
        stored_hash = users[username]['password_hash']
        salt = users[username]['salt']
        if verify_password(password, stored_hash, salt):
            st.session_state.user = username
            st.session_state.auth_status = True
            st.session_state.attempt_count = 0
            st.session_state.lockout_until = None
            go_to_home()
            return True
    
    st.session_state.attempt_count += 1
    if st.session_state.attempt_count >= 3:
        st.session_state.lockout_until = datetime.now() + timedelta(minutes=2)
        st.session_state.attempt_count = 0
    
    return False

def register_user(username, password):
    users = load_users()
    if username in users:
        return False
    
    password_hash, salt = hash_password(password)
    users[username] = {
        'password_hash': password_hash,
        'salt': salt,
        'created_at': datetime.now().isoformat()
    }
    save_users(users)
    return True

# UI Components
def render_header():
    st.markdown('<div class="title-box"><h1>🔒 Secure Data Vault</h1></div>', unsafe_allow_html=True)

def render_footer():
    st.markdown("""
    <div style="position: fixed; bottom: 0; width: 100%; text-align: center; padding: 10px; background-color: #121212;">
        <p style="color: #888888;">© 2025 Secure Data Vault | Privacy & Security</p>
    </div>
    """, unsafe_allow_html=True)

def render_sidebar():
    with st.sidebar:
        st.markdown('<h2 style="text-align: center;">Navigation</h2>', unsafe_allow_html=True)
        
        if st.session_state.auth_status:
            st.markdown(f'<p class="info-text">Logged in as: {st.session_state.user}</p>', unsafe_allow_html=True)
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🏠 Home", use_container_width=True):
                    go_to_home()
            with col2:
                if st.button("🚪 Logout", use_container_width=True):
                    st.session_state.auth_status = False
                    st.session_state.user = None
                    go_to_login()
                    st.rerun()
            
            st.divider()
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔒 Store", use_container_width=True):
                    go_to_store()
            with col2:
                if st.button("🔑 Retrieve", use_container_width=True):
                    go_to_retrieve()
        else:
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔑 Login", use_container_width=True):
                    go_to_login()
            with col2:
                if st.button("📝 Register", use_container_width=True):
                    go_to_register()
        
        st.divider()
        st.markdown("""
        <div class="special-box">
            <h3>Security Tips</h3>
            <ul>
                <li>Use strong, unique passkeys</li>
                <li>Never share your passkeys</li>
                <li>Logout when finished</li>
            </ul>
        </div>
        """, unsafe_allow_html=True)

# Page Renderers
def render_home_page():
    st.markdown('<h2 style="text-align: center;">Welcome to Your Secure Data Vault</h2>', unsafe_allow_html=True)
    
    st.markdown("""
    <div class="special-box">
        <h3>What would you like to do today?</h3>
        <p>This secure vault lets you encrypt and store sensitive information with custom passkeys.</p>
    </div>
    """, unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        <div class="special-box" style="height: 200px;">
            <h3 style="text-align: center;">🔒 Store Data</h3>
            <p>Encrypt and securely store your sensitive information with a custom passkey.</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Store New Data", use_container_width=True):
            go_to_store()
            
    with col2:
        st.markdown("""
        <div class="special-box" style="height: 200px;">
            <h3 style="text-align: center;">🔑 Retrieve Data</h3>
            <p>Access your encrypted data by providing the correct passkey.</p>
        </div>
        """, unsafe_allow_html=True)
        if st.button("Retrieve Data", use_container_width=True):
            go_to_retrieve()
    
    st.markdown("""
    <div class="special-box">
        <h3>How it Works</h3>
        <ul>
            <li><strong>Store Data:</strong> Enter your text with a unique passkey</li>
            <li><strong>Retrieve Data:</strong> Use your passkey to decrypt and view your data</li>
            <li><strong>Security:</strong> After 3 failed attempts, you'll need to log in again</li>
            <li><strong>Privacy:</strong> Your data is securely encrypted with advanced algorithms</li>
        </ul>
    </div>
    """, unsafe_allow_html=True)

def render_store_page():
    st.markdown('<h2 style="text-align: center;">Store Encrypted Data</h2>', unsafe_allow_html=True)
    
    st.markdown("""
    <div class="special-box">
        <p>Enter the data you want to encrypt and provide a secure passkey to protect it.</p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.form("store_data_form"):
        data_title = st.text_input("Data Title", placeholder="Give your data a recognizable title")
        data_content = st.text_area("Data Content", height=150, placeholder="Enter the sensitive information you want to encrypt")
        passkey = st.text_input("Encryption Passkey", type="password", placeholder="Create a strong passkey")
        confirm_passkey = st.text_input("Confirm Passkey", type="password", placeholder="Re-enter your passkey")
        
        submit_button = st.form_submit_button("Encrypt & Store Data")
        
        if submit_button:
            if not data_title or not data_content or not passkey:
                st.error("Please fill in all fields.")
            elif passkey != confirm_passkey:
                st.error("Passkeys do not match!")
            else:
                encrypted_data = encrypt_data(data_content, passkey)
                
                if st.session_state.user not in st.session_state.data_store:
                    st.session_state.data_store[st.session_state.user] = {}
                
                st.session_state.data_store[st.session_state.user][data_title] = encrypted_data
                save_data()
                
                st.success("✅ Data encrypted and stored successfully!")
                st.markdown('<p class="warning-text">Remember your passkey! Without it, your data cannot be recovered.</p>', unsafe_allow_html=True)

def render_retrieve_page():
    st.markdown('<h2 style="text-align: center;">Retrieve Encrypted Data</h2>', unsafe_allow_html=True)
    
    if check_lockout():
        return
    
    if st.session_state.user not in st.session_state.data_store or not st.session_state.data_store[st.session_state.user]:
        st.info("You don't have any stored data yet. Go to the Store Data page to add some!")
        return
    
    st.markdown("""
    <div class="special-box">
        <p>Select the data you want to retrieve and enter the passkey to decrypt it.</p>
        <p class="warning-text">Note: After 3 failed attempts, you'll be locked out temporarily.</p>
    </div>
    """, unsafe_allow_html=True)
    
    data_titles = list(st.session_state.data_store[st.session_state.user].keys())
    selected_title = st.selectbox("Select data to retrieve", data_titles)
    
    with st.form("retrieve_data_form"):
        passkey = st.text_input("Enter Passkey", type="password", placeholder="Enter the passkey for this data")
        submit_button = st.form_submit_button("Decrypt Data")
        
        if submit_button:
            if not passkey:
                st.error("Please enter a passkey.")
            else:
                encrypted_info = st.session_state.data_store[st.session_state.user][selected_title]
                decrypted_data = decrypt_data(encrypted_info, passkey)
                
                if decrypted_data:
                    st.session_state.attempt_count = 0
                    
                    st.success("✅ Data decrypted successfully!")
                    st.markdown('<div class="special-box">', unsafe_allow_html=True)
                    st.markdown("### Decrypted Content")
                    st.text_area("", value=decrypted_data, height=200, disabled=True)
                    st.markdown('</div>', unsafe_allow_html=True)
                    
                    # Show metadata
                    timestamp = datetime.fromisoformat(encrypted_info['timestamp'])
                    st.info(f"This data was encrypted on {timestamp.strftime('%B %d, %Y at %H:%M:%S')}")
                else:
                    st.session_state.attempt_count += 1
                    remaining_attempts = 3 - st.session_state.attempt_count
                    
                    if remaining_attempts > 0:
                        st.error(f"❌ Incorrect passkey! Remaining attempts: {remaining_attempts}")
                    else:
                        st.session_state.lockout_until = datetime.now() + timedelta(minutes=2)
                        st.session_state.attempt_count = 0
                        st.error("🔒 Too many failed attempts! You are locked out for 2 minutes.")
                        time.sleep(1)
                        go_to_login()
                        st.rerun()

def render_login_page():
    st.markdown('<h2 style="text-align: center;">Login to Secure Data Vault</h2>', unsafe_allow_html=True)
    
    if check_lockout():
        return
    
    st.markdown("""
    <div class="special-box">
        <p>Enter your credentials to access your secure vault.</p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.form("login_form"):
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type="password", placeholder="Enter your password")
        submit_button = st.form_submit_button("Login")
        
        if submit_button:
            if not username or not password:
                st.error("Please enter both username and password.")
            elif login_user(username, password):
                st.success("✅ Login successful!")
                st.rerun()
            else:
                remaining_attempts = 3 - st.session_state.attempt_count
                if remaining_attempts > 0:
                    st.error(f"❌ Invalid credentials! Remaining attempts: {remaining_attempts}")
                else:
                    st.error("🔒 Too many failed attempts! You are locked out for 2 minutes.")
    
    st.markdown("""
    <div style="text-align: center; margin-top: 20px;">
        <p>Don't have an account? <span style="color: #6E00B3; cursor: pointer;" onclick="document.querySelector('button:contains(\"Register\")').click()">Register here</span></p>
    </div>
    """, unsafe_allow_html=True)

def render_register_page():
    st.markdown('<h2 style="text-align: center;">Create New Account</h2>', unsafe_allow_html=True)
    
    st.markdown("""
    <div class="special-box">
        <p>Create a new account to start using the Secure Data Vault.</p>
    </div>
    """, unsafe_allow_html=True)
    
    with st.form("register_form"):
        username = st.text_input("Username", placeholder="Choose a username")
        password = st.text_input("Password", type="password", placeholder="Create a strong password")
        confirm_password = st.text_input("Confirm Password", type="password", placeholder="Re-enter your password")
        submit_button = st.form_submit_button("Register")
        
        if submit_button:
            if not username or not password:
                st.error("Please fill in all fields.")
            elif password != confirm_password:
                st.error("Passwords do not match!")
            elif register_user(username, password):
                st.success("✅ Account created successfully! You can now login.")
                go_to_login()
                st.rerun()
            else:
                st.error("Username already exists. Please choose another one.")
    
    st.markdown("""
    <div style="text-align: center; margin-top: 20px;">
        <p>Already have an account? <span style="color: #6E00B3; cursor: pointer;" onclick="document.querySelector('button:contains(\"Login\")').click()">Login here</span></p>
    </div>
    """, unsafe_allow_html=True)

# Main App
def main():
    # Load data at startup
    load_data()
    
    # Render common components
    render_header()
    render_sidebar()
    
    # Check authentication
    if not st.session_state.auth_status and st.session_state.current_page not in ["login", "register"]:
        go_to_login()
    
    # Render the correct page
    if st.session_state.current_page == "home":
        render_home_page()
    elif st.session_state.current_page == "store":
        render_store_page()
    elif st.session_state.current_page == "retrieve":
        render_retrieve_page()
    elif st.session_state.current_page == "login":
        render_login_page()
    elif st.session_state.current_page == "register":
        render_register_page()
    
    render_footer()

if __name__ == "__main__":
    main()