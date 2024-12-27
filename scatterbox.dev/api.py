import os
import random
import string
from urllib.parse import quote, urlparse
import urllib.parse
import uuid
import datetime
import base64

import bcrypt
import mysql.connector
from flask import Flask, jsonify, request, send_file, current_app, send_from_directory, render_template, abort, session, redirect, render_template_string, url_for, Response
import logging
from flask_cors import CORS
from dotenv import load_dotenv
import time
import random
import binascii
from werkzeug.utils import secure_filename
import json
import requests
from functools import wraps
import math
import os
import base64
import random
import string
import datetime
from cryptography.fernet import Fernet, InvalidToken
import cryptography
import pyotp
import qrcode
import io
import threading
import urllib

# Google OAuth imports
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError

load_dotenv('/var/sites/.env')

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
GOOGLE_REDIRECT_URI = 'https://scatterbox.dev/api/math/oauth/google/callback'
GOOGLE_LINK_REDIRECT_URI = 'https://scatterbox.dev/api/math/oauth/google/link/callback'

# Discord OAuth Configuration
API_ENDPOINT = 'https://discord.com/api/v10'
CLIENT_ID = '1322216623461105734'
CLIENT_SECRET = os.environ.get('DISCORD_CLIENT_SECRET')
REDIRECT_URI = 'https://scatterbox.dev/api/math/oauth/discord/callback'
REDIRECT_URI2 = 'https://scatterbox.dev/api/math/oauth/discord/link/callback'

def exchange_code(code, redirect_uri=REDIRECT_URI):
  data = {
    'grant_type': 'authorization_code',
    'code': code,
    'redirect_uri': redirect_uri
  }
  headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
  }
  r = requests.post('%s/oauth2/token' % API_ENDPOINT, data=data, headers=headers, auth=(CLIENT_ID, CLIENT_SECRET))
  r.raise_for_status()
  return r.json()

def refresh_token(refresh_token):
  data = {
    'grant_type': 'refresh_token',
    'refresh_token': refresh_token
  }
  headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
  }
  r = requests.post('%s/oauth2/token' % API_ENDPOINT, data=data, headers=headers, auth=(CLIENT_ID, CLIENT_SECRET))
  r.raise_for_status()
  return r.json()

def create_oauth_flow(redirect_uri):
    """Create a new OAuth flow instance with the specified redirect URI"""
    return Flow.from_client_config(
        {
            "web": {
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [GOOGLE_REDIRECT_URI, GOOGLE_LINK_REDIRECT_URI]
            }
        },
        scopes=['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile'],
        redirect_uri=redirect_uri
    )

# Ensure necessary files and directories exist
def ensure_file_exists(file_path, default_content=None):
    if not os.path.exists(file_path):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as file:
            if default_content:
                json.dump(default_content, file)

# Ensure encryption key files exist and generate keys if they don't
def ensure_encryption_key(file_path):
    if not os.path.exists(file_path):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        key = Fernet.generate_key()
        with open(file_path, 'wb') as file:
            file.write(key)

# Define paths to necessary files
ENCRYPTION_KEY_FILE = 'var/Site-resources/Encryption/Encryption.key'
CHAT_ENCRYPTION_KEY_FILE = 'var/Site-resources/Encryption/Chat_Encryption.key'
MAINTENANCE_FILE = 'var/Site-resources/json/scatterbox.dev/maintenance.json'
BANNED_IPS_FILE = 'var/Site-resources/json/scatterbox.dev/banned_ips.json'
LOCKED_ACCOUNTS_FILE = 'var/Site-resources/json/scatterbox.dev/locked_accounts.json'

# Ensure necessary files exist
ensure_encryption_key(ENCRYPTION_KEY_FILE)
ensure_encryption_key(CHAT_ENCRYPTION_KEY_FILE)
ensure_file_exists(MAINTENANCE_FILE, default_content={'maintenance_mode': False})
ensure_file_exists(BANNED_IPS_FILE, default_content={})
ensure_file_exists(LOCKED_ACCOUNTS_FILE, default_content={})

with open('var/Site-resources/Encryption/Encryption.key', 'rb') as key_file:
    key = key_file.read()
fernet = Fernet(key)

with open('var/Site-resources/Encryption/Chat_Encryption.key', 'rb') as key_file:
    key = key_file.read()
fernet_chat = Fernet(key)

public_folder = '/var/sites/scatterbox.dev/html'

app = Flask('app')
CORS(app)

# Set the secret key from environment variable
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise ValueError("No SECRET_KEY set in environment variables")

# Define the path to the JSON file
MAINTENANCE_FILE = 'var/Site-resources/json/scatterbox.dev/maintenance.json'

blocked_ips = [
    
]
b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
#gen funcs---------------------------------------------------------------------------------------------
# Load the maintenance mode state from the JSON file¨
def load_maintenance_state():
    if os.path.exists(MAINTENANCE_FILE):
        with open(MAINTENANCE_FILE, 'r') as file:
            data = json.load(file)
            return data.get('maintenance_mode', True)
    return True

# Save the maintenance mode state to the JSON file
def save_maintenance_state(state):
    data = {'maintenance_mode': state}
    with open(MAINTENANCE_FILE, 'w') as file:
        json.dump(data, file)

def load_json(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            return json.load(file)

def save_json(file_path, data):
    with open(file_path, 'w') as file:
        json.dump(data, file)

# Decorator to check if the IP is blocked
def check_blocked_ip(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_ip = request.headers.get('X-Real-IP', request.remote_addr)
        if client_ip in blocked_ips:
            app.logger.warn(f"A request has been blocked due to blacklisted IP{client_ip}")
            return send_from_directory(public_folder, 'Access_Denied.html'), 403
        
        user_agent = request.headers.get('User-Agent')
        if user_agent == 'Go-http-client/1.1':
            app.logger.warn(f"A request has been blocked due to blacklisted User-Agent: {user_agent}")
            return send_from_directory(public_folder, 'Access_Denied.html'), 403
        
        return f(*args, **kwargs)
    return decorated_function



def generate_token(user_id):
    # Encode the user ID in base64
    user_id_encoded = base64.b64encode(str(user_id).encode()).decode()
    
    # Generate a random string to ensure the token is unique
    random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=150 - len(user_id_encoded)))
    
    # Combine the encoded user ID and random string
    token = user_id_encoded + "/./" + random_string
    
    # Encrypt the token using Fernet
    encrypted_token = fernet.encrypt(token.encode()).decode()
    
    # Set the issued date
    issued_at = datetime.datetime.now()
    
    # Store the encrypted token in the database
    conn, cursor = get_db_connection()
    cursor.execute("INSERT INTO tokens (user_id, token, issued_at) VALUES (%s, %s, %s)", (user_id, encrypted_token, issued_at))
    conn.commit()
    cursor.close()
    conn.close()
    
    return encrypted_token

def validate_token(token, encrypted_token):
    app.logger.warn(f"Encrypted token: {encrypted_token}")
    app.logger.warn(f"Token: {token}")
    conn, cursor = get_db_connection()
    cursor.execute("SELECT * FROM tokens WHERE token = %s", (encrypted_token,))
    token_data = cursor.fetchone()
    cursor.close()
    conn.close()
    
    if not token_data:
        return False
    
    # Check if the token is expired
    issued_at = token_data['issued_at']
    if issued_at + datetime.timedelta(days=10) < datetime.datetime.now():
        # Optionally, delete expired tokens from the database
        conn, cursor = get_db_connection()
        cursor.execute("DELETE FROM tokens WHERE token = %s", (encrypted_token,))
        conn.commit()
        cursor.close()
        conn.close()
        return False
    
    decrypted_token = fernet.decrypt(token_data['token'].encode()).decode()
    
    if decrypted_token != token:
        return False
    
    return True

# Validate user tokens
def require_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Session-Token')
        encrypted_token = request.headers.get('encrypted-token')
        user_id = request.headers.get('user-id')
        
        if not token or not validate_token(token, encrypted_token):
            return jsonify({"message": "Invalid or missing session token"}), 403
        
        # Retrieve the user_id associated with the token
        conn, cursor = get_db_connection()
        cursor.execute("SELECT user_id FROM tokens WHERE token = %s", (encrypted_token,))
        token_data = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if not token_data:
            return jsonify({"message": "Invalid session token"}), 403
        
        token_user_id = token_data['user_id']
        
        # Check if the token's user_id matches the requested user_id
        if str(token_user_id) != str(user_id):
            app.logger.warn(f"Token does not match the requested user ID: {token_user_id} != {user_id}")
            return jsonify({"message": "Token does not match the requested user ID"}), 403

        return f(*args, **kwargs)
    return decorated_function

def require_moderator_token(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Session-Token')
        encrypted_token = request.headers.get('encrypted-token')
        if not token or not validate_token(token, encrypted_token):
            return jsonify({"message": "Invalid or missing session token"}), 403
        
        # Retrieve the user_id associated with the token
        conn, cursor = get_db_connection()
        cursor.execute("SELECT user_id FROM tokens WHERE token = %s", (encrypted_token,))
        token_data = cursor.fetchone()
        
        if not token_data:
            cursor.close()
            conn.close()
            return jsonify({"message": "Invalid session token"}), 403
        
        user_id = token_data['user_id']
        
        # Check if the user is a moderator
        cursor.execute("SELECT moderator FROM achievements WHERE user_id = %s", (user_id,))
        user_status = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user_status or not user_status['moderator']:
            return jsonify({"message": "User is not a moderator"}), 403

        return f(*args, **kwargs)
    return decorated_function

def is_vpn_or_proxy(ip):
    # Make a request to the VPN Detection API
    url = f"https://vpnapi.io/api/{ip}?key={os.environ.get('VPN_detection_API_key')}"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        security = data['security']
        vpn = security['vpn']
        proxy = security['proxy']
        tor = security['tor']
        relay = security['relay']
        
        if vpn or proxy or tor or relay:
            ip_types = []
            if vpn:
                ip_types.append('VPN')
            if proxy:
                ip_types.append('Proxy')
            if tor:
                ip_types.append('Tor')
            if relay:
                ip_types.append('Relay')
            
            app.logger.warn(f"IP {ip} is detected as: {', '.join(ip_types)}")
            return True
        return security['vpn'] or security['proxy'] or security['tor'] or security['relay']
    else:
        # Handle API request errors
        print(f"Error: {response.status_code} - {response.text}")
        return False

# Decoding function
def decode(data):
    # Remove any characters not in the Base64 set (ignore non-base64 characters)
    filtered_data = ''.join([char for char in data if char in b + '='])
    
    # Prepare the binary representation of the encoded data
    binary_data = ''.join(
        bin(b.index(char))[2:].zfill(6) for char in filtered_data if char != '='
    )
    
    # Split binary data into 8-bit chunks and convert to ASCII characters
    decoded_string = ''.join(
        chr(int(binary_data[i:i + 8], 2)) for i in range(0, len(binary_data), 8)
        if len(binary_data[i:i + 8]) == 8
    )
    
    return decoded_string

# math func---------------------------------------------------------------------------------------------
def clear_expired_activations():
    conn, cursor = get_db_connection()
    try:
        one_hour_ago = datetime.datetime.now() - datetime.timedelta(hours=1)
        cursor.execute("DELETE FROM pending_2fa WHERE created_at < %s", (one_hour_ago,))
        conn.commit()
    except mysql.connector.Error as error:
        app.logger.error(f"Failed to clear expired pending 2FA activations: {error}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()


def generate_password():
    length = 255

    # Define character sets
    upper_case = string.ascii_uppercase
    lower_case = string.ascii_lowercase
    special_characters = string.punctuation
    digits = string.digits

    # Ensure the password includes at least one of each character type
    password = [
        random.choice(upper_case),
        random.choice(lower_case),
        random.choice(special_characters),
        random.choice(digits)
    ]

    # Fill the rest of the password length with a mix of all characters
    all_characters = upper_case + lower_case + special_characters + digits
    password += random.choices(all_characters, k=length-4)

    # Shuffle the password list to ensure randomness
    random.shuffle(password)

    # Convert the list to a string and return it
    return ''.join(password)

def get_db_connection():
    conn = mysql.connector.connect(
        host=os.environ['DBHOST'],
        database=os.environ['DBDATABASE'],
        user=os.environ['DBUSER'],
        password=os.environ['DBPASSWORD']
    )
    cursor = conn.cursor(dictionary=True)
    return conn, cursor

def update_achievements():
    conn, cursor = get_db_connection()
    try:
        cursor.execute('DELETE FROM achievements WHERE user_id NOT IN (SELECT user_id FROM users);')
        
        cursor.execute("""
        UPDATE achievements
        SET reached_100_points = 1
        WHERE user_id IN (SELECT user_id FROM users WHERE points >= 100);
        """)
        conn.commit()  # Commit and fetch the result here to ensure the command finishes
        cursor.execute("""
        UPDATE achievements
        SET reached_500_points = 1
        WHERE user_id IN (SELECT user_id FROM users WHERE points >= 500);
        """)
        conn.commit()  # Commit and fetch the result here to ensure the command finishes
        cursor.execute("""
        UPDATE achievements
        SET reached_1000_points = 1
        WHERE user_id IN (SELECT user_id FROM users WHERE points >= 1000);
        """)
        conn.commit()  # Commit and fetch the result here to ensure the command finishes
    finally:
        cursor.close()
        conn.close()

def convert_to_boolean(data, keys_to_convert):
    """
    Convert specified keys in the dictionary to boolean.
    """
    return {k: (v == 1 if k in keys_to_convert else v) for k, v in data.items()}
# chat func---------------------------------------------------------------------------------------------

def get_chat_db_connection():
    conn = mysql.connector.connect(
        host=os.environ['ChatDbHost'],
        database=os.environ['ChatDbDatabase'],
        user=os.environ['ChatDbUser'],
        password=os.environ['ChatDbPassword']
    )
    cursor = conn.cursor(dictionary=True)
    return conn, cursor

def chat_login(key):
    with open('Chat_Encryption.key', 'rb') as key_file:
        key_instore = key_file.read()
    if key == key_instore:
        return True
    else:
        return False
    
# General endpoints-------------------------------------------------------------------------------------

@app.route('/api/prox', methods=['*'])
def mirror_request():
    # Extract the target URL from the custom "url" header
    target_url = decode(request.headers.get("url"))
    (f"Target URL: {target_url}")
    if request.headers.get("key") != os.environ.get("proxy"):
        app.logger.info("Error: bad 'key' header.")
        return "Error: bad 'key' header.", 400
    if not target_url:
        app.logger.info("Error: Missing 'url' header.")
        return "Error: Missing 'url' header.", 400

    # Validate the target URL
    allowed_domains = ["example.com", "another-allowed-domain.com"]
    parsed_url = urlparse(target_url)
    if parsed_url.hostname not in allowed_domains:
        return "Error: 'url' header points to an unauthorized domain.", 400

    # Prepare the forwarded request
    headers = {key: value for key, value in request.headers if key.lower() != 'host'}
    headers.pop('url', None)  # Remove the "url" header to avoid sending it to the target server
    headers.pop('key', None)
    app.logger.info(f"Forwarding headers: {headers}")

    # Forward the request
    try:
        response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            params=request.args
        )
        app.logger.info(f"Response status code: {response.status_code}")
        app.logger.info(f"Response headers: {response.headers}")
        
        # Construct the response to return to the original requester
        forwarded_response = Response(response.content, response.status_code)
        for key, value in response.headers.items():
            forwarded_response.headers[key] = value

        return forwarded_response

    except requests.exceptions.RequestException as e:
        app.logger.info(f"Request forwarding failed: {e}")
        return f"Request forwarding failed: {e}", 500

@app.route('/api/verify-key', methods=['POST'])
@check_blocked_ip
def verify_api_key1():
    received_key = request.headers.get('API-Key')
    if received_key == os.environ.get('site_dev_api_key'):
        return jsonify({"message": "API Key is valid"}), 200
    else:
        return jsonify({"error": "Invalid API Key"}), 401

@app.route('/api/lock-site', methods=['POST'])
@check_blocked_ip
def lock_site():
    received_key = request.headers.get('API-Key')
    if received_key == os.environ.get('site_dev_api_key'):
        save_maintenance_state(True)
        app.logger.warn(f'Maintenance on maintenance mode variable: {load_maintenance_state()}')
        return jsonify({"message": "Site is now in maintenance mode"}), 200
    else:
        return jsonify({"error": "Invalid API Key"}), 401

@app.route('/api/unlock-site', methods=['POST'])
@check_blocked_ip
def unlock_site():
    received_key = request.headers.get('API-Key')
    if received_key == os.environ.get('site_dev_api_key'):
        save_maintenance_state(False)
        app.logger.warn(f'Maintenance off maintenance mode variable: {load_maintenance_state()}')
        return jsonify({"message": "Site has exited maintenance mode"}), 200
    else:
        return jsonify({"error": "Invalid API Key"}), 401


@app.route('/community-projects', methods=['GET'])
@check_blocked_ip
def community_projects1():
    featured_projects = []
    community_projects = []

    # Define the path to the community projects folder
    projects_folder = os.path.join(public_folder, 'community-projects')

    # List of featured project names
    featured_list = ['tangos-site', 'meme-archive']  # Replace with actual featured project names

    # Loop through all folders in the community projects directory
    for project_name in os.listdir(projects_folder):
        project_path = os.path.join(projects_folder, project_name)
        if os.path.isdir(project_path):
            if project_name in featured_list:
                featured_projects.append(project_name)
            else:
                community_projects.append(project_name)

    # Create a dictionary to hold the project lists
    projects_data = {
        "featured_projects": featured_projects,
        "community_projects": community_projects
    }

    # Return the data as JSON
    return jsonify(projects_data), 200



@app.route('/api/is-up', methods=['GET'])
@check_blocked_ip
def is_up():
    try:
        connection, _ = get_db_connection()  # Unpack the tuple returned by get_db_connection
        if connection.is_connected():
            cursor = connection.cursor()
            cursor.execute("SELECT 1")
            cursor.fetchone()
            cursor.close()
            connection.close()
            return 'True', 200
        else:
            app.logger.error("Database connection failed.")
            return 'False', 500
    except Exception as e:
        app.logger.error(f"Database health check failed: {e}")
        return 'False', 500

@app.route('/<path:path>')
@check_blocked_ip
def serve_public(path):
    app.logger.warn(f'IP: {request.headers.get("X-Real-IP", request.remote_addr)}')
    maintenance_mode = load_maintenance_state()
    if maintenance_mode and request.cookies.get('bypass_maintenance') != '1' and not path.endswith('dev.html') and not path.endswith('dev_login.html'):
        app.logger.warn(f'Redirected to maintenance mode maintenance mode variable: {maintenance_mode}')
        return send_from_directory(public_folder, 'Maintenance.html'), 503
    
    if path.startswith('Community-api/radim/Uploads/'):
        return send_from_directory(public_folder, 'Access_Denied.html'), 403
    
    #if path.endswith('math/login.html') or path.endswith('math/signup.html'):
        if is_vpn_or_proxy(request.headers.get('X-Real-IP', request.remote_addr)):
            return send_from_directory(public_folder, 'vpn_blocked.html'), 403
    
    app.logger.info(f"Requested path: {path}")
    normalized_path = os.path.normpath(path)
    full_path = os.path.join(public_folder, normalized_path)
    app.logger.info(f"Full path: {full_path}")

    if not full_path.startswith(public_folder):
        app.logger.warning(f"Attempted access to invalid path: {full_path}")
        return send_from_directory(public_folder, 'index.html')

    if os.path.isdir(full_path):
        app.logger.info(f"Path is a directory, serving index.html from {full_path}")
        return send_from_directory(full_path, 'index.html')
    
    try:
        return send_from_directory(public_folder, normalized_path)
    except FileNotFoundError:
        app.logger.warning(f"File not found: {normalized_path}, serving index.html instead")
        return send_from_directory(public_folder, 'index.html')

@app.route('/')
@check_blocked_ip
def serve_index():
    maintenance_mode = load_maintenance_state()
    if maintenance_mode and request.cookies.get('bypass_maintenance') != '1':
        app.logger.warn(f'Redirected to maintenance mode maintenance mode variable: {maintenance_mode}')
        return send_from_directory(public_folder, 'Maintenance.html'), 503
    
    app.logger.info("Serving index.html for root URL")
    return send_from_directory(public_folder, 'index.html')

@app.route('/debug')
@check_blocked_ip
def debug():
    return send_file('html/500.html'), 500

@app.route('/api/ai-moderation', methods=['POST'])
@check_blocked_ip
def ai_moderation():
    content = request.headers.get('Content')
    if not content:
        return jsonify({'error': 'Content header missing'}), 400

    url = 'https://moderationapi.com/api/v1/moderate/text'
    headers = {
        'Authorization': os.environ.get('AI_MODERATION_API_KEY'),
        'Content-Type': 'application/json'
    }
    data = {'value': content}
    try:
        response = requests.post(url, headers=headers, json=data)
        response.raise_for_status()
        api_response = response.json()
        flagged = api_response.get('flagged', False)
        return {"message": flagged}, 200
    except requests.RequestException as e:
        app.logger.error(f"Error contacting moderation API: {e}")
        return jsonify({'error': 'Failed to process moderation request'}), 500

@app.errorhandler(404)
@check_blocked_ip
def page_not_found(e):
    return send_from_directory(public_folder, '404.html'), 404

@app.errorhandler(500)
@check_blocked_ip
def page_not_found(e):
    return send_from_directory('html/', '500.html'), 500


# math endpoints----------------------------------------------------------------------------------------

@app.route('/api/math/is-up', methods=['GET'])
@check_blocked_ip
def is_up1():
    return 'True', 200

BANNED_IPS_FILE = '/var/Site-resources/json/scatterbox.dev/banned_ips.json'
LOCKED_ACCOUNTS_FILE = '/var/Site-resources/json/scatterbox.dev/locked_accounts.json'

def load_locked_accounts():
    return load_json(LOCKED_ACCOUNTS_FILE)

def save_locked_accounts(data):
    save_json(LOCKED_ACCOUNTS_FILE, data)

def ban_ip(ip):
    banned_ips = load_json(BANNED_IPS_FILE)
    banned_ips[ip] = time.time()
    save_json(BANNED_IPS_FILE, banned_ips)

def unban_ip(ip):
    banned_ips = load_json(BANNED_IPS_FILE)
    if ip in banned_ips:
        del banned_ips[ip]
    save_json(BANNED_IPS_FILE, banned_ips)

def add_locked_account(ip, user_id):
    locked_accounts = load_locked_accounts()
    if ip not in locked_accounts:
        locked_accounts[ip] = []
    if user_id not in locked_accounts[ip]:
        locked_accounts[ip].append(user_id)
    save_locked_accounts(locked_accounts)

def unlock_accounts_by_ip(ip):
    locked_accounts = load_locked_accounts()
    if ip in locked_accounts:
        del locked_accounts[ip]
    save_locked_accounts(locked_accounts)

@app.route('/api/math/auth/remove-2fa', methods=['DELETE'])
@check_blocked_ip
@require_token
def remove_2fa():
    user_id = request.headers.get('user-id')
    code = request.headers.get('code')

    if not user_id or not code:
        return jsonify({"message": "User ID and code are required"}), 400

    conn, cursor = get_db_connection()
    
    try:
        cursor.execute("SELECT secret FROM mfa WHERE user_id = %s", (user_id,))
        mfa_record = cursor.fetchone()
        if not mfa_record:
            return jsonify({"message": "2FA is not enabled for this user"}), 404

        secret = fernet.decrypt(mfa_record['secret']).decode()

        totp = pyotp.TOTP(secret)
        if not totp.verify(code):
            return jsonify({"message": "Invalid 2FA code"}), 400

        cursor.execute("DELETE FROM mfa WHERE user_id = %s", (user_id,))
        conn.commit()

        return jsonify({"message": "2FA removed successfully"}), 200

    except Exception as error:
        app.logger.error(f"Failed to remove 2FA: {error}")
        conn.rollback()
        return jsonify({"message": "Internal server error"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/math/auth/generate-2fa', methods=['GET'])
@check_blocked_ip
@require_token
def generate_2fa():
    # Generate a secret for the user
    secret = pyotp.random_base32()
    user_id = request.headers.get('user-id')  # Assuming user_id is passed in the request headers
    password = request.headers.get('password')  # Assuming password is passed in the request headers

    if not user_id or not password:
        return jsonify({"message": "User ID and password are required"}), 400

    conn, cursor = get_db_connection()
    
    try:
        # Verify the user's password
        cursor.execute("SELECT user_password FROM users WHERE user_id = %s", (user_id,))
        result = cursor.fetchone()
        if not result:
            return jsonify({"message": "User not found"}), 404
        stored_password = result['user_password']
        if not bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
            return jsonify({"message": "Invalid password"}), 401

        cursor.execute("SELECT * FROM mfa WHERE user_id = %s", (user_id,))
        existing_record = cursor.fetchone()
        if existing_record:
            return jsonify({"message": "2FA is already enabled for this user"}), 400
        
        cursor.execute("SELECT * FROM pending_2fa WHERE user_id = %s", (user_id,))
        pending_record = cursor.fetchone()
        if pending_record:
            cursor.execute("DELETE FROM pending_2fa WHERE user_id = %s", (user_id,))
        
        secret_db = fernet.encrypt(secret.encode()).decode()
        cursor.execute("INSERT INTO pending_2fa (user_id, secret, created_at) VALUES (%s, %s, %s)", (user_id, secret_db, datetime.datetime.now()))
        conn.commit()
        
        # Start a separate thread to check for expired pending activations
        threading.Thread(target=clear_expired_activations, daemon=True).start()  # Use daemon=True to ensure the thread exits with the program
        
    except Exception as error:  # Use a general exception to catch all errors
        app.logger.error(f"Failed to insert pending 2FA record into database: {error}")
        conn.rollback()
        return jsonify({"message": "Internal server error"}), 500  # Return an error response
    finally:
        cursor.close()
        conn.close()

    conn, cursor = get_db_connection()

    # Get the user's username based on their user_id
    try:
        cursor.execute("SELECT username FROM users WHERE user_id = %s", (user_id,))
        result = cursor.fetchone()
        if result:
            username = result['username']
        else:
            app.logger.error(f"No username found for user ID: {user_id}")
            return jsonify({"message": "User not found"}), 404  # Return an error response
    except Exception as error:
        app.logger.error(f"Error fetching username: {error}")
        return jsonify({"message": "Internal server error"}), 500  # Return an error response

    # Generate the provisioning URI (otpauth://...) for the QR code
    totp = pyotp.TOTP(secret)
    otpauth_url = totp.provisioning_uri(name=username, issuer_name="Scatterbox Math")

    # Generate the QR code from the otpauth URL
    qr = qrcode.make(otpauth_url)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    qr_image = base64.b64encode(buffer.getvalue()).decode()

    # Return the QR code as base64 image (for scanning)
    return jsonify({
        'qrcode': f"data:image/png;base64,{qr_image}"  # Send this to the frontend to scan
    })

@app.route('/api/math/auth/activate-2fa', methods=['POST'])
@check_blocked_ip
@require_token
def activate_2fa():
    user_id = request.headers.get('user-id')
    code = request.headers.get('code')  # Assuming the code is sent in the request body
    turnstile_token = request.headers.get('CF-Turnstile-Token')

    # Verify Turnstile token
    secret_key = os.environ.get('TURNSTILE_SECRET_KEY')
    response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data={
        'secret': secret_key,
        'response': turnstile_token
    })

    result = response.json()

    if not result.get('success'):
        return jsonify({'message': 'Turnstile verification failed.'}), 400


    if not user_id or not code:
        return jsonify({"message": "User ID and code are required"}), 400

    conn, cursor = get_db_connection()

    try:
        # Retrieve the pending 2FA record
        cursor.execute("SELECT secret FROM pending_2fa WHERE user_id = %s", (user_id,))
        pending_record = cursor.fetchone()

        if not pending_record:
            return jsonify({"message": "No pending 2FA setup found for this user"}), 404

        secret = pending_record['secret']
        secret = fernet.decrypt(secret.encode()).decode()
        totp = pyotp.TOTP(secret)

        # Verify the provided code
        if not totp.verify(code):
            return jsonify({"message": "Invalid 2FA code"}), 400
    
        secret_db = fernet.encrypt(secret.encode()).decode()

        # Move the record to the mfa table
        cursor.execute("INSERT INTO mfa (user_id, secret) VALUES (%s, %s)", (user_id, secret_db))
        cursor.execute("DELETE FROM pending_2fa WHERE user_id = %s", (user_id,))
        conn.commit()

        return jsonify({"message": "2FA activated successfully"}), 200

    except Exception as error:
        app.logger.error(f"Error activating 2FA: {error}")
        conn.rollback()
        return jsonify({"message": "Internal server error"}), 500

    finally:
        cursor.close()
        conn.close()

@app.route('/api/math/2fa-login', methods=['POST'])
@check_blocked_ip
def mfa_login():
    conn, cursor = get_db_connection()

    if 'username' not in request.headers or 'password' not in request.headers:
        cursor.close()
        conn.close()
        return {"message": "Invalid username or password"}, 401

    data = request.headers
    username = data['username']
    password = data['password']
    code = data.get('code')  # Get the 2FA code from the request headers
    client_ip = request.headers.get('X-Real-IP', request.remote_addr)

    query_lock_and_mod = """
    SELECT u.locked, u.moderator, u.user_password, u.user_id, u.points
    FROM users u
    LEFT JOIN achievements a ON u.user_id = a.user_id
    WHERE u.username = %s
    """

    cursor.execute(query_lock_and_mod, (username,))
    user_info = cursor.fetchone()

    if user_info is None:
        cursor.close()
        conn.close()
        return {"message": "Invalid username or password"}, 401

    if user_info['locked'] == 1:
        add_locked_account(client_ip, user_info['user_id'])
        ban_ip(client_ip)
        cursor.execute("INSERT INTO login_attempts (user_id, ip) VALUES (%s, %s)", (user_info['user_id'], client_ip))
        conn.commit()
        cursor.close()
        conn.close()
        return {"message": "Account is locked"}, 601

    stored_password = user_info['user_password']

    # Check the password using bcrypt
    if not bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
        cursor.close()
        conn.close()
        return {"message": "Invalid username or password"}, 401

    # Check if the IP is banned
    banned_ips = load_json(BANNED_IPS_FILE)
    if client_ip in banned_ips:
        cursor.execute("UPDATE users SET locked = TRUE WHERE user_id = %s", (user_info['user_id'],))
        conn.commit()
        add_locked_account(client_ip, user_info['user_id'])
        cursor.execute("INSERT INTO login_attempts (user_id, ip) VALUES (%s, %s)", (user_info['user_id'], client_ip))
        conn.commit()
        cursor.close()
        conn.close()
        return {"message": "Account is locked due to previous login attempts from this IP"}, 601

    cursor.execute("INSERT INTO login_attempts (user_id, ip) VALUES (%s, %s)", (user_info['user_id'], client_ip))
    conn.commit()

    # Check if there is an active form of multi-factor authentication for the user
    cursor.execute("SELECT * FROM mfa WHERE user_id = %s", (user_info['user_id'],))
    mfa_record = cursor.fetchone()

    if mfa_record:
        if not code:
            cursor.close()
            conn.close()
            return {"message": "2FA code is required"}, 403

        secret = mfa_record['secret']
        secret = fernet.decrypt(secret.encode()).decode()
        totp = pyotp.TOTP(secret)

        # Verify the provided 2FA code
        if not totp.verify(code):
            cursor.close()
            conn.close()
            return {"message": "Invalid 2FA code"}, 403

    # Check for an existing token
    cursor.execute("SELECT token FROM tokens WHERE user_id = %s", (user_info['user_id'],))
    existing_token = cursor.fetchone()

    if existing_token:
        token = existing_token['token']
    else:
        token = generate_token(user_info['user_id'])

    cursor.close()
    conn.close()

    user_info = convert_to_boolean(user_info, ['moderator'])
    try:
        decrypted_token = fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        return {"message": "Failed to decrypt token"}, 500

    return {
        "message": "User logged in successfully",
        "user_id": user_info['user_id'],
        "points": user_info['points'],
        "is_mod": user_info['moderator'],
        "session_token": decrypted_token,
        "encrypted_token": token,
        "mfa_enabled": True
    }, 200




@app.route('/api/math/login', methods=['POST'])
@check_blocked_ip
def login():
    conn, cursor = get_db_connection()

    if 'username' not in request.headers or 'password' not in request.headers:
        cursor.close()
        conn.close()
        return {"message": "Invalid username or password"}, 401

    data = request.headers
    username = data['username']
    password = data['password']
    client_ip = request.headers.get('X-Real-IP', request.remote_addr)

    query_lock_and_mod = """
    SELECT u.locked, u.moderator, u.user_password, u.user_id, u.points
    FROM users u
    LEFT JOIN achievements a ON u.user_id = a.user_id
    WHERE u.username = %s
    """

    cursor.execute(query_lock_and_mod, (username,))
    user_info = cursor.fetchone()

    if user_info is None:
        cursor.close()
        conn.close()
        return {"message": "Invalid username or password"}, 401

    if user_info['locked'] == 1:
        add_locked_account(client_ip, user_info['user_id'])
        ban_ip(client_ip)
        cursor.execute("INSERT INTO login_attempts (user_id, ip) VALUES (%s, %s)", (user_info['user_id'], client_ip))
        conn.commit()
        cursor.close()
        conn.close()
        return {"message": "Account is locked"}, 601

    stored_password = user_info['user_password']

    # Check the password using bcrypt
    try:
        if not bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
            cursor.close()
            conn.close()
            return {"message": "Invalid username or password"}, 401
    except ValueError as e:
        cursor.close()
        conn.close()
        return {"message": f"Password decryption error: {str(e)}"}, 500

    # Check if the IP is banned
    banned_ips = load_json(BANNED_IPS_FILE)
    if client_ip in banned_ips:
        cursor.execute("UPDATE users SET locked = TRUE WHERE user_id = %s", (user_info['user_id'],))
        conn.commit()
        add_locked_account(client_ip, user_info['user_id'])
        cursor.execute("INSERT INTO login_attempts (user_id, ip) VALUES (%s, %s)", (user_info['user_id'], client_ip))
        conn.commit()
        cursor.close()
        conn.close()
        return {"message": "Account is locked due to previous login attempts from this IP"}, 601

    cursor.execute("INSERT INTO login_attempts (user_id, ip) VALUES (%s, %s)", (user_info['user_id'], client_ip))
    conn.commit()

    # Check if there is an active form of multi-factor authentication for the user
    cursor.execute("SELECT * FROM mfa WHERE user_id = %s", (user_info['user_id'],))
    mfa_record = cursor.fetchone()

    if mfa_record:
        cursor.close()
        conn.close()
        return {"message": "Further authentication required"}, 403

    # Check for an existing token
    cursor.execute("SELECT token FROM tokens WHERE user_id = %s", (user_info['user_id'],))
    existing_token = cursor.fetchone()

    if existing_token:
        token = existing_token['token']
    else:
        token = generate_token(user_info['user_id'])

    cursor.close()
    conn.close()

    user_info = convert_to_boolean(user_info, ['moderator'])
    try:
        decrypted_token = fernet.decrypt(token.encode()).decode()
    except InvalidToken:
        token = generate_token(user_info['user_id'])
        try:
            decrypted_token = fernet.decrypt(token.encode()).decode()
        except InvalidToken as e:
            return {"message": f"Failed to decrypt token after regeneration: {str(e)}"}, 500
        return {"message": "Failed to decrypt token"}, 500

    return {
        "message": "User logged in successfully",
        "user_id": user_info['user_id'],
        "points": user_info['points'],
        "is_mod": user_info['moderator'],
        "session_token": decrypted_token,
        "encrypted_token": token,
        "mfa_enabled": False
    }, 200

@app.route('/api/math/signup', methods=['POST'])
@check_blocked_ip
def signup():
    username = request.headers.get('username')
    password = request.headers.get('password')
    turnstile_token = request.headers.get('CF-Turnstile-Token')

    # Verify Turnstile token
    secret_key = os.environ.get('TURNSTILE_SECRET_KEY')
    response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data={
        'secret': secret_key,
        'response': turnstile_token
    })

    result = response.json()

    if not result.get('success'):
        return jsonify({'message': 'Turnstile verification failed.'}), 400

    if not username or not password:
        return {"message": "Username and password are required"}, 400

    conn, cursor = get_db_connection()

    try:
        cursor.execute("SELECT user_id FROM users WHERE username = %s", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            return {"message": "Username already exists"}, 409

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user_id = math.floor(random.randint(1000000000, 9999999999))
        cursor.execute(
            "INSERT INTO users (username, user_password, user_id) VALUES (%s, %s, %s)",
            (username, hashed_password, user_id)
        )
        cursor.execute(
            "INSERT INTO achievements (user_id) VALUES (%s)",
            (user_id,)
        )
        conn.commit()

        return {
            "message": "User registered successfully",
            "user_id": user_id
        }, 201
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Exception occurred: {str(e)}")
        return {"message": "Internal server error"}, 500
    finally:
        cursor.close()
        conn.close()



@app.route('/api/math/add-point', methods=['POST'])
@check_blocked_ip
@require_token
def add_point():
    update_achievements()
    conn, cursor = get_db_connection()

    data = request.headers
    points_str = data['points']
    points_to_add = int(points_str)
    user_id = data['user-id']

    if points_to_add > 5 or points_to_add < -2:
        wipe_query = 'UPDATE users SET points = 0 WHERE user_id = %s'
        cursor.execute(wipe_query, (user_id,))
        conn.commit()
        cursor.close()
        conn.close()
        return {
            "message": "Cheat detected. Account points have been wiped."
        }, 200

    query = 'UPDATE users SET points = points + %s WHERE user_id = %s'
    cursor.execute(query, (points_to_add, user_id))

    # Perform a SELECT query to check if the user exists and get the updated points
    select_query = 'SELECT points FROM users WHERE user_id = %s'
    cursor.execute(select_query, (user_id,))
    result = cursor.fetchone()

    if not result:
        conn.rollback()
        cursor.close()
        conn.close()
        return {"message": "User not found"}, 404

    updated_points = result['points']
    conn.commit()
    cursor.close()
    conn.close()
    return {
        "message": "Points added successfully",
        "points": updated_points
    }, 200



@app.route('/api/math/wipe', methods=['POST'])
@check_blocked_ip
@require_moderator_token
def wipe_points():
    conn, cursor = get_db_connection()
    data = request.headers
    user_id = data.get('user-id')
    api_key = data.get('api-key')

    cursor.execute("SELECT moderator, dev FROM achievements WHERE user_id = %s;", (user_id,))
    user_status = cursor.fetchone()

    is_dev_api_key = api_key == os.environ.get('DEV_API_KEY')

    if not user_status:  # If user does not exist or has no achievements.
        cursor.close()
        conn.close()
        return {"message": "User not found or has no achievements"}, 404

    if user_status['dev'] == 1 and not is_dev_api_key:
        cursor.close()
        conn.close()
        return {"message": "Operation not allowed on developer accounts"}, 403

    if user_status['moderator'] == 1 and not is_dev_api_key:  # mods cannot modify other mods unless it's a dev
        cursor.close()
        conn.close()
        return {"message": "Operation not allowed"}, 403

    if api_key not in [os.environ['API_KEY'], os.environ.get('DEV_API_KEY')]:
        cursor.close()
        conn.close()
        return {"message": "API key invalid or Unauthorized"}, 401

    query = 'UPDATE users SET points = 0 WHERE user_id = %s'
    cursor.execute(query, (user_id,))
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "User points wiped successfully"}, 200

@app.route('/api/math/leaderboard', methods=['GET'])
@check_blocked_ip
def leaderboard():
    conn, cursor = get_db_connection()

    query = 'SELECT username, points FROM users ORDER BY points DESC LIMIT 10'
    cursor.execute(query)
    leaderboard_data = cursor.fetchall()
    cursor.close()
    conn.close()
    return {"leaderboard": leaderboard_data}, 200

@app.route('/api/math/change-name', methods=['PUT'])
@check_blocked_ip
@require_token
def change_name():
    turnstile_token = request.headers.get('CF-Turnstile-Token')

    # Verify Turnstile token
    secret_key = os.environ.get('TURNSTILE_SECRET_KEY')
    response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data={
        'secret': secret_key,
        'response': turnstile_token
    })

    result = response.json()

    if not result.get('success'):
        return jsonify({'message': 'Turnstile verification failed.'}), 400

    conn, cursor = get_db_connection()

    data = request.headers
    user_id = data.get('user-id')
    password = data.get('password')
    new_username = data.get('new-username')

    if not user_id or not password or not new_username:
        cursor.close()
        conn.close()
        return {
            "message": "User ID, password, or new username not provided"
        }, 400

    query = 'SELECT user_password FROM users WHERE user_id = %s'
    cursor.execute(query, (user_id,))
    user = cursor.fetchone()

    db_password = user['user_password']

    if not user or not bcrypt.checkpw(password.encode('utf-8'), db_password.encode('utf-8')):
        cursor.close()
        conn.close()
        return {"message": "Invalid user ID or password"}, 401

    update_query = 'UPDATE users SET username = %s WHERE user_id = %s'
    cursor.execute(update_query, (new_username, user_id))
    conn.commit()

    cursor.close()
    conn.close()
    return {"message": "Username updated successfully"}, 200

@app.route('/api/math/change-password', methods=['PUT'])
@check_blocked_ip
@require_token
def change_password():
    data = request.headers
    user_id = data.get('user-id')
    old_password = data.get('old-password')
    new_password = data.get('new-password')
    turnstile_token = request.headers.get('CF-Turnstile-Token')

    # Verify Turnstile token
    secret_key = os.environ.get('TURNSTILE_SECRET_KEY')
    response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data={
        'secret': secret_key,
        'response': turnstile_token
    })

    result = response.json()

    if not result.get('success'):
        return jsonify({'message': 'Turnstile verification failed.'}), 400


    if not user_id or not old_password or not new_password:
        return {"message": "Headers are is not provided"}, 400

    conn, cursor = get_db_connection()
    cursor.execute('SELECT user_password FROM users WHERE user_id = %s', (user_id,))
    stored_password = cursor.fetchone()
    stored_password = stored_password['user_password']
    if not bcrypt.checkpw(old_password.encode('utf-8'), stored_password.encode('utf-8')):
        cursor.close()
        conn.close()
        return {"message": "Invalid password"}, 401
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    cursor.execute('UPDATE users SET user_password = %s WHERE user_id = %s', (hashed_password, user_id))
    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Password changed successfully"}, 200

@app.route('/api/math/user-achievements', methods=['GET'])
@check_blocked_ip
@require_token
def user_achievements():
    update_achievements()
    conn, cursor = get_db_connection()
    user_id = request.headers.get('user-id')

    query_user_achievements = 'SELECT reached_100_points, reached_500_points, reached_1000_points, dev, moderator FROM achievements WHERE user_id = %s'
    cursor.execute(query_user_achievements, (user_id,))
    user_achievements = cursor.fetchone()

    cursor.close()
    conn.close()

    if user_achievements:
        keys_to_convert = ['reached_100_points', 'reached_500_points', 'reached_1000_points', 'dev', 'moderator']
        user_achievements = convert_to_boolean(user_achievements, keys_to_convert)
        achievements_list = [k for k, v in user_achievements.items() if v]
        return {"achievements": achievements_list}, 200
    else:
        return {"message": "User achievements not found"}, 404

def action_restrictions(cursor, user_id, api_key):
    """
    Validates if an action is permissible based on the user role and API key.
    Checks if the API key is valid and then checks user roles (mod, dev) in the database.
    Returns (permitted: bool, message: str).
    """
    is_dev_api_key = api_key == os.environ.get('DEV_API_KEY')
    is_regular_api_key = api_key == os.environ.get('API_KEY')

    if not (is_dev_api_key or is_regular_api_key):
        return False, "Invalid or unauthorized API key"

    cursor.execute("SELECT moderator, dev FROM users WHERE user_id = %s;", (user_id,))
    user_status = cursor.fetchone()

    if not user_status:
        return False, "User not found or has no achievements"

    user_status = convert_to_boolean(user_status, ['moderator', 'dev'])

    if user_status['dev'] and not is_dev_api_key:
        return False, "Operation not allowed on developer accounts"

    if user_status['moderator'] and not is_dev_api_key:
        return False, "Operation not allowed on moderator accounts"

    return True, "Action permitted"

@app.route('/api/math/delete', methods=['DELETE'])
@check_blocked_ip
@require_moderator_token
def delete_account():
    conn, cursor = get_db_connection()
    api_key = request.headers.get('api-key')
    user_id = request.headers.get('user-id')

    permitted, message = action_restrictions(cursor, user_id, api_key)
    if not permitted:
        cursor.close()
        conn.close()
        return {"message": message}, 403

    deletion_query = "DELETE FROM users WHERE user_id = %s"
    cursor.execute(deletion_query, (user_id,))
    if cursor.rowcount == 0:
        conn.rollback()
        cursor.close()
        conn.close()
        return {"message": "User not found or already deleted"}, 404

    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Account deleted successfully"}, 200

@app.route('/api/math/lock', methods=['PATCH'])
@check_blocked_ip
@require_moderator_token
def lock_account():
    api_key = request.headers.get('api-key')
    user_id = request.headers.get('user-id')

    conn, cursor = get_db_connection()
    permitted, message = action_restrictions(cursor, user_id, api_key)
    if not permitted:
        cursor.close()
        conn.close()
        return {"message": message}, 403

    cursor.execute(
        "UPDATE users SET locked = TRUE WHERE user_id = %s",
        (user_id,))
    if cursor.rowcount == 0:
        conn.rollback()
        cursor.close()
        conn.close()
        return {"message": "User not found or already locked"}, 404

    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Account locked successfully"}, 200

@app.route('/api/math/unlock', methods=['PATCH'])
@check_blocked_ip
@require_moderator_token
def unlock_account():
    api_key = request.headers.get('api-key')
    user_id = request.headers.get('user-id')

    conn, cursor = get_db_connection()
    permitted, message = action_restrictions(cursor, user_id, api_key)
    if not permitted:
        cursor.close()
        conn.close()
        return {"message": message}, 403

    cursor.execute(
        "UPDATE users SET locked = FALSE WHERE user_id = %s",
        (user_id,))
    if cursor.rowcount == 0:
        conn.rollback()
        cursor.close()
        conn.close()
        return {"message": "User not found or already unlocked"}, 404

    try:
        # Get the IPs associated with the locked account
        cursor.execute("SELECT ip FROM login_attempts WHERE user_id = %s", (user_id,))
        ips = cursor.fetchall()

        for ip_entry in ips:
            ip = ip_entry['ip']
            # Unlock all accounts associated with this IP
            cursor.execute("UPDATE users SET locked = FALSE WHERE user_id IN (SELECT user_id FROM login_attempts WHERE ip = %s)", (ip,))
            # Remove the IP from the banned list
            unban_ip(ip)
            # Remove the IP from the locked accounts list
            unlock_accounts_by_ip(ip)
    except mysql.connector.errors.ProgrammingError as e:
        if e.errno == 1146:  # Error code for table doesn't exist
            app.logger.error("Table 'login_attempts' doesn't exist.")
        else:
            raise

    conn.commit()
    cursor.close()
    conn.close()
    return {"message": "Account unlocked successfully"}, 200

@app.route('/api/math/get_api_key', methods=['GET'])
@check_blocked_ip
@require_moderator_token
def get_api_key():
    conn, cursor = get_db_connection()
    username = request.headers.get('username')
    password = request.headers.get('password')
    turnstile_token = request.headers.get('CF-Turnstile-Token')

    # Verify Turnstile token
    secret_key = os.environ.get('TURNSTILE_SECRET_KEY')
    response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data={
        'secret': secret_key,
        'response': turnstile_token
    })

    result = response.json()

    if not result.get('success'):
        return jsonify({'message': 'Turnstile verification failed.'}), 400

    if not username or not password:
        return jsonify({"message": "Username and password are required"}), 400

    query = """
    SELECT u.user_id, a.dev, a.moderator, u.user_password
    FROM users u
    JOIN achievements a ON u.user_id = a.user_id
    WHERE u.username = %s;
    """
    cursor.execute(query, (username,))
    user = cursor.fetchone()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['user_password'].encode('utf-8')):
        # Check if there is an active form of multi-factor authentication for the user
        cursor.execute("SELECT * FROM mfa WHERE user_id = %s", (user['user_id'],))
        mfa_record = cursor.fetchone()

        if mfa_record:
            cursor.close()
            conn.close()
            return {"message": "Further authentication required"}, 403

        user = convert_to_boolean(user, ['dev', 'moderator'])
        if user['dev'] or user['moderator']:
            if user['dev']:
                developer_api_key = os.environ.get('DEV_API_KEY')
                cursor.close()
                conn.close()
                return jsonify({"API_Key": developer_api_key}), 200
            else:
                api_key = os.environ.get('API_KEY')
                cursor.close()
                conn.close()
                return jsonify({"API_Key": api_key}), 200
        else:
            cursor.close()
            conn.close()
            return jsonify({"message": "Unauthorized: User is not a mod or dev"}), 401
    else:
        cursor.close()
        conn.close()
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/api/math/mfa-get-api-key', methods=['GET'])
@check_blocked_ip
@require_moderator_token
def mfa_get_api_key():
    conn, cursor = get_db_connection()
    username = request.headers.get('username')
    password = request.headers.get('password')
    code = request.headers.get('code')  # Get the 2FA code from the request headers
    turnstile_token = request.headers.get('CF-Turnstile-Token')

    # Verify Turnstile token
    secret_key = os.environ.get('TURNSTILE_SECRET_KEY')
    response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data={
        'secret': secret_key,
        'response': turnstile_token
    })

    result = response.json()

    if not result.get('success'):
        return jsonify({'message': 'Turnstile verification failed.'}), 400

    if not username or not password or not code:
        return jsonify({"message": "Username, password, and 2FA code are required"}), 400

    query = """
    SELECT u.user_id, a.dev, a.moderator, u.user_password
    FROM users u
    JOIN achievements a ON u.user_id = a.user_id
    WHERE u.username = %s;
    """
    cursor.execute(query, (username,))
    user = cursor.fetchone()

    if user and bcrypt.checkpw(password.encode('utf-8'), user['user_password'].encode('utf-8')):
        # Check if there is an active form of multi-factor authentication for the user
        cursor.execute("SELECT secret FROM mfa WHERE user_id = %s", (user['user_id'],))
        mfa_record = cursor.fetchone()

        if not mfa_record:
            cursor.close()
            conn.close()
            return {"message": "2FA is not enabled for this user"}, 403

        secret = fernet.decrypt(mfa_record['secret'].encode()).decode()
        totp = pyotp.TOTP(secret)

        # Verify the provided 2FA code
        if not totp.verify(code):
            cursor.close()
            conn.close()
            return {"message": "Invalid 2FA code"}, 403

        user = convert_to_boolean(user, ['dev', 'moderator'])
        if user['dev'] or user['moderator']:
            if user['dev']:
                developer_api_key = os.environ.get('DEV_API_KEY')
                cursor.close()
                conn.close()
                return jsonify({"API_Key": developer_api_key}), 200
            else:
                api_key = os.environ.get('API_KEY')
                cursor.close()
                conn.close()
                return jsonify({"API_Key": api_key}), 200
        else:
            cursor.close()
            conn.close()
            return jsonify({"message": "Unauthorized: User is not a mod or dev"}), 401
    else:
        cursor.close()
        conn.close()
        return jsonify({"message": "Invalid credentials"}), 401
    
@app.route('/api/math/verify-api-key', methods=['GET'])
@check_blocked_ip
@require_moderator_token
def verify_api_key():
    api_key = request.headers.get('api-key')
    valid_api_keys = [os.environ.get('API_KEY'), os.environ.get('DEV_API_KEY')]

    if not api_key:
        return jsonify({"message": "API key is required"}), 400

    if api_key in valid_api_keys:
        return jsonify({"message": "API key is valid"}), 200
    else:
        return jsonify({"message": "Invalid API key"}), 401

@app.route('/api/math/usernames', methods=['GET'])
@check_blocked_ip
@require_moderator_token
def get_usernames():
    api_key = request.headers.get('api-key')
    valid_api_keys = [os.environ.get('API_KEY'), os.environ.get('DEV_API_KEY')]

    if not api_key or api_key not in valid_api_keys:
        return jsonify({"message": "Unauthorized or invalid API key"}), 401

    conn, cursor = get_db_connection()

    try:
        cursor.execute("SELECT username FROM users ORDER BY username ASC")
        usernames = cursor.fetchall()
        return jsonify({"usernames": [user['username'] for user in usernames]}), 200

    except Exception as e:
        return jsonify({"message": f"An error occurred: {e}"}), 500

    finally:
        cursor.close()
        conn.close()
@app.route('/api/math/user-detail', methods=['GET'])
@check_blocked_ip
@require_moderator_token
def get_user_detail():
    api_key = request.headers.get('api-key')
    username_query = request.headers.get('username')

    if not api_key or not username_query:
        return jsonify({"message": "API key and username are required"}), 400

    is_mod = api_key == os.environ.get('API_KEY')
    is_dev = api_key == os.environ.get('DEV_API_KEY')

    conn, cursor = get_db_connection()
    try:
        cursor.execute(
            """
        SELECT u.user_id, u.username, u.locked, a.moderator, a.dev, u.points
        FROM users u
        LEFT JOIN achievements a ON u.user_id = a.user_id
        WHERE u.username = %s;
        """, (username_query,))
        user_detail = cursor.fetchone()

        if not user_detail:
            return jsonify({"message": "User not found"}), 404
        if is_dev:
            cursor.execute("SELECT token FROM tokens WHERE user_id = %s", (user_detail['user_id'],))
            token = cursor.fetchone()
            if token:
                user_detail['token'] = token['token']
                try:
                    decrypted_token = fernet.decrypt(user_detail['token'].encode()).decode()
                    user_detail['decrypted_token'] = decrypted_token
                except Exception as token_error:
                    app.logger.error(f"Error decrypting token: {str(token_error)}")
                    user_detail['decrypted_token'] = "Error: Unable to decrypt token"
            else:
                user_detail['token'] = "No token found"
                user_detail['decrypted_token'] = "No token found"
        else:
            user_detail['token'] = "No token found"
            user_detail['decrypted_token'] = "No token found"

        # Only convert 'moderator', 'dev', 'locked' keys to boolean
        keys_to_convert = ['moderator', 'dev', 'locked']
        user_detail = convert_to_boolean(user_detail, keys_to_convert)

        if is_mod:
            if user_detail['moderator'] or user_detail['dev']:
                user_detail['user_password'] = 'redacted'
        elif not is_dev:
            user_detail['user_password'] = 'redacted'

        return jsonify({"user_detail": user_detail}), 200

    except Exception as e:
        app.logger.error(f"An error occurred in get_user_detail: {str(e)}")
        return jsonify({"message": "An internal error has occurred!"}), 500

    finally:
        cursor.close()
        conn.close()


@app.route('/api/math/mod-add-point', methods=['POST'])
@check_blocked_ip
@require_moderator_token
def mod_add_point():
    conn, cursor = get_db_connection()
    api_key = request.headers.get('api-key')
    user_id = request.headers.get('user-id')

    permitted, message = action_restrictions(cursor, user_id, api_key)
    if not permitted:
        cursor.close()
        conn.close()
        return jsonify({"message": message}), 403

    data = request.headers
    points_str = data.get('points')
    points_to_add = int(points_str) if points_str else 0

    query = 'UPDATE users SET points = points + %s WHERE user_id = %s'
    cursor.execute(query, (points_to_add, user_id))
    conn.commit()
    cursor.close()
    conn.close()
    return {
        "message": "Points added successfully"
    }, 200

@app.route('/api/math/generate_login_link', methods=['GET'])
@check_blocked_ip
@require_moderator_token
def generate_login_link():
    api_key = request.headers.get('api-key')
    user_id = request.headers.get('id')
    
    if not user_id:
        return jsonify({"message": "User ID is required"}), 400

    key = generate_password()

    try:
        conn, cursor = get_db_connection()
        
        permitted, message = action_restrictions(cursor, user_id, api_key)
        if not permitted:
            cursor.close()
            conn.close()
            return {"message": message}, 403
            
        cursor.execute("SELECT login_key FROM login_keys WHERE user_id = %s", (user_id,))
        existing_key = cursor.fetchone()

        if existing_key:  # Ensure that existing_key is not None and index is accessed properly    
            key_value = quote(str(existing_key['login_key']))  # Ensure it's treated as a string    
            login_link = f"https://math-felix.replit.app/moderator_login.html?key={key_value}"
            return jsonify({"login_link": login_link}), 200  # Corrected to return 200 status code for existing key

        cursor.execute("INSERT INTO login_keys (user_id, login_key) VALUES (%s, %s)", (user_id, key))
        conn.commit()

        cursor.close()
        conn.close()

        login_link = f"https://scatterbox.dev/math/moderator_login.html?key={quote(key)}"
        return jsonify({"login_link": login_link})

    except Exception as e:
        return jsonify({"message": f"Internal server error: {str(e)}"}), 500

@app.route('/api/math/verify_moderator_login_key', methods=['GET'])
@check_blocked_ip
def verify_moderator_login_key():
    key = request.args.get('key')
    print(key)
    if not key:
        return jsonify({"message": "Login key is required"}), 400

    try:
        conn, cursor = get_db_connection()

        cursor.execute("SELECT user_id FROM login_keys WHERE login_key = %s", (key,))
        user_id_result = cursor.fetchone()
        if user_id_result is None or not user_id_result['user_id']:
            cursor.close()
            conn.close()
            return jsonify({"message": "Invalid login key"}), 401

        user_id = user_id_result['user_id']
        query = """
        SELECT u.user_id, u.points, a.moderator 
        FROM users u
        LEFT JOIN achievements a ON u.user_id = a.user_id
        WHERE u.user_id = %s
        """
        cursor.execute(query, (user_id,))
        user_result = cursor.fetchone()

        keys_to_convert = ['moderator']
        if user_result:
            user = convert_to_boolean(user_result, keys_to_convert)
        else:
            user = None

        # Check for an existing token
        cursor.execute("SELECT token FROM tokens WHERE user_id = %s", (user_id,))
        existing_token = cursor.fetchone()

        if existing_token and user:
            token = existing_token['token']
        elif user:
            token = generate_token(user['user_id'])
        else:
            cursor.close()
            conn.close()
            return jsonify({"message": "Invalid user data"}), 401

        # Delete the login key after use
        cursor.execute('DELETE FROM login_keys WHERE login_key = %s', (key,))
        conn.commit()

        cursor.close()
        conn.close()

        decrypted_token = fernet.decrypt(token.encode()).decode()

        if user:
            return {
                "message": "Moderator logged in successfully",
                "user_id": user['user_id'],
                "points": user['points'],
                "is_mod": user['moderator'],
                "encrypted_token": token,
                "session_token": decrypted_token
            }, 200
        else:
            return {"message": "Invalid login key"}, 401

    except Exception as e:
        current_app.logger.error(f"Internal server error: {str(e)}")
        return jsonify({"message": "An internal error has occurred"}), 500
    
@app.route('/api/math/GrantMod', methods=['PATCH'])
@check_blocked_ip
@require_moderator_token
def Grant_Mod():
    data = request.headers
    userid = data.get('user_id')
    if data.get('api-key') != os.environ.get('DEV_API_KEY'):
        return jsonify({"message": "Unauthorized: API key is invalid or missing"}), 401
    conn, cursor = get_db_connection()

    try:
        cursor.execute('UPDATE achievements SET moderator = 1 WHERE user_id = %s', (userid,))
        cursor.execute('UPDATE users SET moderator = 1 WHERE user_id = %s', (userid,))
        if cursor.rowcount == 0:
            conn.rollback()
            return {"message": "Operation failed: No such user found or the user is already a moderator"}, 404
        conn.commit()
        return {"message": "Moderator status granted successfully to user"}, 200
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Failed to grant moderator status: {str(e)}")
        return {"message": "Failed to grant moderator status due to an internal error"}, 500

@app.route('/api/math/RevokeMod', methods=['PATCH'])
@check_blocked_ip
@require_moderator_token
def Revoke_Mod():
    data = request.headers
    userid = data.get('user_id')
    if data.get('api-key') != os.environ.get('DEV_API_KEY'):
        return jsonify({"message": "Unauthorized: API key is invalid or missing"}), 401
    conn, cursor = get_db_connection()

    try:
        cursor.execute('UPDATE achievements SET moderator = 0 WHERE user_id = %s', (userid,))
        cursor.execute('UPDATE users SET moderator = 0 WHERE user_id = %s', (userid,))
        if cursor.rowcount == 0:
            conn.rollback()
            return {"message": "Operation failed: No such user found or the user is not a moderator"}, 404
        conn.commit()
        return {"message": "Moderator status revoked successfully from user"}, 200
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Failed to revoke moderator status: {str(e)}")
        return {"message": "Failed to revoke moderator status due to an internal error"}, 500
    
@app.route('/api/math/admin/change-password', methods=['PUT'])
@check_blocked_ip
@require_moderator_token
def admin_change_password():
    data = request.headers
    user_id = data.get('user-id')
    new_password = data.get('new-password')
    if data.get('api-key') != os.environ.get('DEV_API_KEY'):
        return jsonify({"message": "Unauthorized: API key is invalid or missing"}), 401

    if not user_id or not new_password:
        return {"message": "User ID or new password not provided"}, 400

    conn, cursor = get_db_connection()
    try:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute('UPDATE users SET user_password = %s WHERE user_id = %s', (hashed_password, user_id))
        if cursor.rowcount == 0:
            conn.rollback()
            return {"message": "Operation failed: No such user found"}, 404
        conn.commit()
        return {"message": "Password changed successfully"}, 200
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Failed to change password: {str(e)}")
        return {"message": "Failed to change password due to an internal error"}, 500
    finally:
        cursor.close()
        conn.close()

@app.route('/api/math/reset-password-2', methods=['PUT'])
@check_blocked_ip
def reset_password():
    data = request.headers
    new_password = data.get('new-password')
    reset_key = data.get('reset-key')
    reset_key = urllib.parse.unquote(reset_key)
    turnstile_token = data.get('CF-Turnstile-Token')

    if not new_password or not reset_key:
        return {"message": "New password or reset key not provided"}, 400

    if not turnstile_token:
        return {"message": "Turnstile verification token is missing"}, 400

    # Verify Turnstile token
    response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data={
        'secret': os.environ.get('TURNSTILE_SECRET_KEY'),
        'response': turnstile_token
    })
    verification_response = response.json()
    if not verification_response.get('success'):
        return {"message": "Turnstile verification failed"}, 403

    conn, cursor = get_db_connection()
    try:
        cursor.execute('SELECT user_id FROM Reset_keys WHERE `key` = %s', (reset_key,))
        result = cursor.fetchone()
        if not result or 'user_id' not in result:
            return {"message": "Invalid reset key"}, 404
        
        user_id = result['user_id']
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        cursor.execute('UPDATE users SET user_password = %s WHERE user_id = %s', (hashed_password, user_id))
        conn.commit()

        return {"message": "Password reset successfully"}, 200
    except Exception as e:
        conn.rollback()
        current_app.logger.error(f"Failed to reset password: {str(e)}")
        return {"message": "Failed to reset password due to an internal error"}, 500
    finally:
        cursor.close()
        conn.close()





@app.route('/api/math/password-reset', methods=['PATCH'])
@check_blocked_ip
def password_reset():
    data = request.headers
    email = data.get('email')

    if not email:
        return {"message": "Email not provided"}, 400

    conn, cursor = get_db_connection()
    try:
        cursor.execute('SELECT user_id FROM users WHERE email = %s', (email,))
        result = cursor.fetchone()
        if not result or 'user_id' not in result:
            return {"message": "Invalid email"}, 404
        
        user_id = result['user_id']  # Get user_id from the email

        # Generate reset key similar to moderator login keys
        reset_key = generate_password()
        cursor.execute('INSERT INTO Reset_keys (user_id, `key`) VALUES (%s, %s)', (user_id, reset_key))  # Use backticks around 'key'
        conn.commit()

        cursor.execute('SELECT username FROM users WHERE user_id = %s', (user_id,))
        result = cursor.fetchone()
        username = result['username'] if result else None
        
      # Input values
        email_address = email  # Replace with the actual email
        name = username  # Replace with the actual username
        team = "scatterbox"
        product_name = "scatterbox math"
        encoded_reset_key = urllib.parse.quote(reset_key)  # Encode the reset key
        password_reset_link = f"https://scatterbox.dev/math/password-reset.html?key={encoded_reset_key}"  # Use the encoded reset key

        # Construct payload as a dictionary
        payload = {
            "mail_template_key": "13ef.303e4f520ebc5a4.k1.cf46b860-ba16-11ef-986f-cabb711367dc.193c52386e6",
            "from": {
                "address": "noreply@scatterbox.dev",
                "name": "noreply"
            },
            "to": [
                {
                    "email_address": {
                        "address": email_address,
                        "name": name
                    }
                }
            ],
            "merge_info": {
                "password_reset_link": password_reset_link,
                "name": name,
                "team": team,
                "product_name": product_name
            }
        }

        # Serialize the payload to JSON
        json_payload = json.dumps(payload)

        # Headers
        headers = {
            'Accept': "application/json",
            'Content-Type': "application/json",
            'Authorization': "Zoho-enczapikey yA6KbHtcuQmhlm4ER0lr15WLoYs5/qEwjHm15SC3eJdzIoTn3KE3gUVvINHoIzaO0YDY5/pWONgWdY7tvotbeJdhYIMCf5TGTuv4P2uV48xh8ciEYNYlhp+rBrcZF6ZLdBkmDCs0QvNt"
        }

        # API URL
        url = "https://api.zeptomail.eu/v1.1/email/template"

        # Make the POST request
        response = requests.post(url, data=json_payload, headers=headers)

        # Debugging response
        app.logger.warn("Status Code:", response.status_code)
        app.logger.warn("Response:", response.text)
        return {"message": "Password reset email sent successfully"}, 200
    finally:
        cursor.close()
        conn.close()

@app.route('/api/math/change-email', methods=['PUT'])
@check_blocked_ip
@require_token
def change_email():
    data = request.headers
    user_id = data.get('user-id')
    new_email = data.get('new-email')
    password = data.get('password')
    turnstile_token = data.get('CF-Turnstile-Token')

    if not user_id or not new_email or not password or not turnstile_token:
        return {"message": "Missing required fields"}, 400

    conn, cursor = get_db_connection()
    try:
        cursor.execute('SELECT user_password FROM users WHERE user_id = %s', (user_id,))
        result = cursor.fetchone()
        
        # Check if result is None or if the password check fails
        if not result or not bcrypt.checkpw(password.encode('utf-8'), result['user_password'].encode('utf-8')):
            return {"message": "Password is incorrect"}, 401

        cursor.execute('UPDATE users SET email = %s WHERE user_id = %s', (new_email, user_id))
        if cursor.rowcount == 0:
            conn.rollback()
            return {"message": "Operation failed: No such user found"}, 404
        conn.commit()
        return {"message": "Email changed successfully"}, 200
    finally:
        cursor.close()
        conn.close()

@app.route('/api/math/oauth/google/start', methods=['GET'])
@check_blocked_ip
def start_google_oauth():
    """Start the Google OAuth flow"""
    flow = create_oauth_flow(GOOGLE_REDIRECT_URI)
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    session['oauth_state'] = state
    session['flow_redirect_uri'] = GOOGLE_REDIRECT_URI
    return jsonify({"authorization_url": authorization_url}), 200

@app.route('/api/math/oauth/google/login', methods=['GET'])
@check_blocked_ip
def google_oauth_callback1():
    """Handle the Google OAuth callback"""
    try:
        # Get the authorization code from the callback
        code = request.args.get('code')
        if not code:
            return jsonify({"message": "No authorization code received"}), 400

        # Create flow with the stored redirect URI
        flow = create_oauth_flow(GOOGLE_REDIRECT_URI)

        # Exchange the authorization code for credentials
        flow.fetch_token(code=code)
        credentials = flow.credentials

        # Get user info from Google
        userinfo_response = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {credentials.token}'}
        )
        userinfo = userinfo_response.json()

        if not userinfo.get('email_verified'):
            return jsonify({"message": "Google account email not verified"}), 400

        email = userinfo['email']
        name = userinfo.get('name', email.split('@')[0])

        # Check if user exists
        conn, cursor = get_db_connection()
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            # Create new user
            user_id = math.floor(random.randint(1000000000, 9999999999))
            password = generate_password()  # Generate a random password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Insert new user
            cursor.execute(
                "INSERT INTO users (username, user_password, user_id, email) VALUES (%s, %s, %s, %s)",
                (name, hashed_password, user_id, email)
            )
            cursor.execute(
                "INSERT INTO achievements (user_id) VALUES (%s)",
                (user_id,)
            )
            conn.commit()
        else:
            user_id = user['user_id']

        # Generate session token
        token = generate_token(user_id)

        # Get user info
        cursor.execute("""
            SELECT u.points, a.moderator 
            FROM users u
            LEFT JOIN achievements a ON u.user_id = a.user_id
            WHERE u.user_id = %s
        """, (user_id,))
        user_info = cursor.fetchone()

        cursor.close()
        conn.close()

        try:
            decrypted_token = fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            return jsonify({"message": "Failed to generate secure token"}), 500

        # Return success response with tokens and user info
        response_data = {
            "message": "Successfully authenticated with Google",
            "user_id": user_id,
            "points": user_info['points'],
            "is_mod": bool(user_info['moderator']),
            "session_token": decrypted_token,
            "encrypted_token": token,
            "mfa_enabled": False
        }

        # Redirect to dashboard with parameters
        params = urllib.parse.urlencode(response_data)
        return redirect(f'/math/dashboard.html?{params}')

    except Exception as e:
        app.logger.error(f"Google OAuth error: {str(e)}")
        return jsonify({"message": "Authentication failed"}), 500

@app.route('/api/math/oauth/google/link/start', methods=['GET'])
@check_blocked_ip
@require_token
def start_google_link():
    """Start the Google OAuth flow for linking an account"""
    user_id = request.headers.get('user-id')
    if not user_id:
        return jsonify({"message": "User ID is required"}), 400

    # Store the user_id in session for the callback
    session['linking_user_id'] = user_id
    
    flow = create_oauth_flow(GOOGLE_LINK_REDIRECT_URI)
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    session['oauth_state'] = state
    session['flow_redirect_uri'] = GOOGLE_LINK_REDIRECT_URI
    return jsonify({"authorization_url": authorization_url}), 200

@app.route('/api/math/oauth/google/link/callback', methods=['GET'])
@check_blocked_ip
def google_link_callback():
    """Handle the Google OAuth callback for account linking"""
    try:
        # Get the user_id from session
        user_id = session.get('linking_user_id')
        if not user_id:
            return jsonify({"message": "No user ID found in session"}), 400

        # Get the authorization code from the callback
        code = request.args.get('code')
        if not code:
            return jsonify({"message": "No authorization code received"}), 400

        # Exchange the authorization code for credentials
        flow = create_oauth_flow(GOOGLE_LINK_REDIRECT_URI)  # Create flow instance
        flow.redirect_uri = GOOGLE_LINK_REDIRECT_URI  # Explicitly set the redirect URI
        flow.fetch_token(code=code)
        credentials = flow.credentials

        # Get user info from Google
        userinfo_response = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {credentials.token}'}
        )
        userinfo = userinfo_response.json()

        if not userinfo.get('email_verified'):
            return jsonify({"message": "Google account email not verified"}), 400

        email = userinfo['email']

        # Check if the Google account is already linked to another user
        conn, cursor = get_db_connection()
        cursor.execute("SELECT user_id FROM users WHERE email = %s AND user_id != %s", (email, user_id))
        existing_link = cursor.fetchone()

        if existing_link:
            cursor.close()
            conn.close()
            return jsonify({"message": "This Google account is already linked to another user"}), 400

        # Update the user's email
        cursor.execute("UPDATE users SET email = %s WHERE user_id = %s", (email, user_id))
        conn.commit()
        cursor.close()
        conn.close()

        # Clear the session
        session.pop('linking_user_id', None)
        session.pop('oauth_state', None)

        # Redirect to settings page with success message
        return redirect('/math/settings.html?message=Google account linked successfully')

    except Exception as e:
        app.logger.error(f"Google account linking error: {str(e)}")
        return jsonify({"message": "Failed to link Google account"}), 500

@app.route('/api/math/oauth/google/signup', methods=['POST'])
@check_blocked_ip
def google_signup():
    """Handle Google account signup with custom username"""
    try:
        username = request.headers.get('Username')
        password = request.headers.get('Password')
        google_token = request.headers.get('Google-Token')
        turnstile_token = request.headers.get('CF-Turnstile-Token')

        if not username or not password or not google_token or not turnstile_token:
            return jsonify({"message": "Missing required fields"}), 400

        # Verify Turnstile token
        response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data={
            'secret': os.environ.get('TURNSTILE_SECRET_KEY'),
            'response': turnstile_token
        })
        if not response.json().get('success'):
            return jsonify({"message": "Turnstile verification failed"}), 400

        # Get user info from Google
        userinfo_response = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {google_token}'}
        )
        userinfo = userinfo_response.json()

        if not userinfo.get('email_verified'):
            return jsonify({"message": "Google account email not verified"}), 400

        email = userinfo['email']

        # Check if email already exists
        conn, cursor = get_db_connection()
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"message": "Email already registered"}), 400

        # Check if username exists
        cursor.execute("SELECT user_id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"message": "Username already taken"}), 400

        # Create new user
        user_id = math.floor(random.randint(1000000000, 9999999999))
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cursor.execute(
            "INSERT INTO users (username, user_password, user_id, email) VALUES (%s, %s, %s, %s)",
            (username, hashed_password, user_id, email)
        )
        cursor.execute(
            "INSERT INTO achievements (user_id) VALUES (%s)",
            (user_id,)
        )
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            "message": "Account created successfully",
            "user_id": user_id
        }), 201

    except Exception as e:
        app.logger.error(f"Google signup error: {str(e)}")
        return jsonify({"message": "Failed to create account"}), 500

@app.route('/api/math/oauth/google/callback', methods=['GET'])
@check_blocked_ip
def google_oauth_callback():
    """Handle the Google OAuth callback"""
    try:
        code = request.args.get('code')
        if not code:
            return jsonify({"message": "No authorization code received"}), 400

        redirect_uri = session.get('flow_redirect_uri')
        if not redirect_uri:
            return jsonify({"message": "No redirect URI found in session"}), 400

        flow = create_oauth_flow(redirect_uri)
        flow.fetch_token(code=code)
        credentials = flow.credentials

        userinfo_response = requests.get(
            'https://www.googleapis.com/oauth2/v3/userinfo',
            headers={'Authorization': f'Bearer {credentials.token}'}
        )
        userinfo = userinfo_response.json()

        if not userinfo.get('email_verified'):
            return jsonify({"message": "Google account email not verified"}), 400

        email = userinfo['email']

        # Check if user exists
        conn, cursor = get_db_connection()
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if not user:
            # Redirect to signup page with Google token
            params = urllib.parse.urlencode({
                'google_token': credentials.token,
                'email': email,
                'name': userinfo.get('name', '')
            })
            return redirect(f'/math/google_signup.html?{params}')

        user_id = user['user_id']

        # Check for 2FA
        cursor.execute("SELECT * FROM mfa WHERE user_id = %s", (user_id,))
        mfa_record = cursor.fetchone()

        if mfa_record:
            # Store credentials in session and redirect to 2FA page
            params = {
                'google_token': credentials.token,
                'user_id': user_id,
                'api_endpoint': '/api/math/oauth/google/verify-2fa', 
                'redirect_url': '/math/dashboard.html',
                'request_method': 'POST',
                'response_keys': json.dumps(['message', 'user_id', 'points', 'is_mod', 'session_token', 'encrypted_token', 'mfa_enabled']),
                'redir': '/math/2fa.html'
            }
            params = urllib.parse.urlencode(params)
            return redirect(f'/math/add_prams.html?{params}')

        # Generate session token
        token = generate_token(user_id)

        # Get user info
        cursor.execute("""
            SELECT u.points, a.moderator 
            FROM users u
            LEFT JOIN achievements a ON u.user_id = a.user_id
            WHERE u.user_id = %s
        """, (user_id,))
        user_info = cursor.fetchone()

        cursor.close()
        conn.close()

        try:
            decrypted_token = fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            return jsonify({"message": "Failed to generate secure token"}), 500

        response_data = {
            "message": "Successfully authenticated with Google",
            "user_id": user_id,
            "points": user_info['points'],
            "is_mod": bool(user_info['moderator']),
            "session_token": decrypted_token,
            "encrypted_token": token,
            "mfa_enabled": False,
            "redir": "/math/dashboard.html"
        }

        params = urllib.parse.urlencode(response_data)
        return redirect(f'/math/add_prams.html?{params}')

    except Exception as e:
        app.logger.error(f"Google OAuth error: {str(e)}")
        return jsonify({"message": "Authentication failed"}), 500

@app.route('/api/math/oauth/google/verify-2fa', methods=['POST'])
@check_blocked_ip
def verify_google_2fa():
    """Verify 2FA code for Google OAuth login"""
    try:
        code = request.headers.get('code')
        if not code:
            return jsonify({"message": "2FA code is required"}), 400

        google_creds = request.headers.get('googlecredentials')
        if not google_creds:
            return jsonify({"message": "No pending Google authentication"}), 400

        try:
            google_creds = json.loads(google_creds)
            user_id = google_creds['user_id']
        except (json.JSONDecodeError, KeyError):
            return jsonify({"message": "Invalid Google credentials format"}), 400

        conn, cursor = get_db_connection()
        cursor.execute("SELECT secret FROM mfa WHERE user_id = %s", (user_id,))
        mfa_record = cursor.fetchone()

        if not mfa_record:
            cursor.close()
            conn.close()
            return jsonify({"message": "2FA not enabled for this account"}), 400

        secret = fernet.decrypt(mfa_record['secret'].encode()).decode()
        totp = pyotp.TOTP(secret)

        if not totp.verify(code):
            cursor.close()
            conn.close()
            return jsonify({"message": "Invalid 2FA code"}), 400

        # Get user info
        cursor.execute("""
            SELECT u.points, a.moderator 
            FROM users u
            LEFT JOIN achievements a ON u.user_id = a.user_id
            WHERE u.user_id = %s
        """, (user_id,))
        user_info = cursor.fetchone()

        # Generate session token
        token = generate_token(user_id)

        cursor.close()
        conn.close()

        # Clear the session
        session.pop('google_credentials', None)

        try:
            decrypted_token = fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            return jsonify({"message": "Failed to generate secure token"}), 500

        return jsonify({
            "message": "Successfully authenticated",
            "user_id": user_id,
            "points": user_info['points'],
            "is_mod": bool(user_info['moderator']),
            "session_token": decrypted_token,
            "encrypted_token": token,
            "mfa_enabled": True
        }), 200

    except Exception as e:
        app.logger.error(f"Google 2FA verification error: {str(e)}")
        return jsonify({"message": "Authentication failed"}), 500

@app.route('/api/math/oauth/discord/callback', methods=['GET'])
@check_blocked_ip
def discord_oauth_callback():
    """Handle the Discord OAuth callback"""
    try:
        code = request.args.get('code')
        if not code:
            return jsonify({"message": "No authorization code received"}), 400
        
        token_data = exchange_code(code)
        access_token = token_data['access_token']
        
        # Get user info from Discord API
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        user_response = requests.get(f'{API_ENDPOINT}/users/@me', headers=headers)
        user_response.raise_for_status()
        user_data = user_response.json()

        discord_id = user_data.get('id')
        email = user_data.get('email')

        if not discord_id:
            return jsonify({"message": "Could not get Discord user ID"}), 400

        # Check if user exists by Discord ID or email
        conn, cursor = get_db_connection()
        cursor.execute("SELECT user_id FROM users WHERE discord_link_id = %s OR email = %s", (discord_id, email))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            # Redirect to signup page with Discord token
            params = urllib.parse.urlencode({
                'discord_token': access_token,
                'email': email,
                'name': user_data.get('username', '')
            })
            return redirect(f'/math/discord_signup.html?{params}')

        user_id = user['user_id']

        # Check for 2FA
        conn, cursor = get_db_connection()
        cursor.execute("SELECT * FROM mfa WHERE user_id = %s", (user_id,))
        mfa_record = cursor.fetchone()

        if mfa_record:
            # Store credentials in session and redirect to 2FA page
            params = {
                'discord_token': access_token,
                'user_id': user_id,
                'api_endpoint': '/api/math/oauth/discord/verify-2fa',
                'redirect_url': '/math/dashboard.html',
                'request_method': 'POST',
                'response_keys': json.dumps(['message', 'user_id', 'points', 'is_mod', 'session_token', 'encrypted_token', 'mfa_enabled']),
                'redir': '/math/2fa.html'
            }
            cursor.close()
            conn.close()
            return redirect(f'/math/add_prams.html?{urllib.parse.urlencode(params)}')

        # Generate session token
        token = generate_token(user_id)

        # Get user info
        cursor.execute("""
            SELECT u.points, a.moderator 
            FROM users u
            LEFT JOIN achievements a ON u.user_id = a.user_id
            WHERE u.user_id = %s
        """, (user_id,))
        user_info = cursor.fetchone()

        # Update Discord link ID if not already set
        cursor.execute("UPDATE users SET discord_link_id = %s WHERE user_id = %s AND discord_link_id IS NULL", (discord_id, user_id))
        conn.commit()
        cursor.close()
        conn.close()

        try:
            decrypted_token = fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            return jsonify({"message": "Failed to generate secure token"}), 500

        response_data = {
            "message": "Successfully authenticated with Discord",
            "user_id": user_id,
            "points": user_info['points'],
            "is_mod": bool(user_info['moderator']),
            "session_token": decrypted_token,
            "encrypted_token": token,
            "mfa_enabled": False,
            "redir": "/math/dashboard.html"
        }

        return redirect(f'/math/add_prams.html?{urllib.parse.urlencode(response_data)}')

    except Exception as e:
        app.logger.error(f"Discord OAuth error: {str(e)}")
        return jsonify({"message": "Authentication failed"}), 500

@app.route('/api/math/oauth/discord/signup', methods=['POST'])
@check_blocked_ip
def discord_signup():
    """Handle Discord account signup with custom username"""
    try:
        username = request.headers.get('Username')
        password = request.headers.get('Password')
        discord_token = request.headers.get('Discord-Token')
        turnstile_token = request.headers.get('CF-Turnstile-Token')

        if not username or not password or not discord_token or not turnstile_token:
            return jsonify({"message": "Missing required fields"}), 400

        # Verify Turnstile token
        response = requests.post('https://challenges.cloudflare.com/turnstile/v0/siteverify', data={
            'secret': os.environ.get('TURNSTILE_SECRET_KEY'),
            'response': turnstile_token
        })
        if not response.json().get('success'):
            return jsonify({"message": "Turnstile verification failed"}), 400

        # Get user info from Discord
        headers = {
            'Authorization': f'Bearer {discord_token}'
        }
        user_response = requests.get(f'{API_ENDPOINT}/users/@me', headers=headers)
        user_response.raise_for_status()
        user_data = user_response.json()

        discord_id = user_data.get('id')
        email = user_data.get('email')

        if not discord_id:
            return jsonify({"message": "Could not get Discord user ID"}), 400

        # Check if Discord ID or email already exists
        conn, cursor = get_db_connection()
        cursor.execute("SELECT user_id FROM users WHERE discord_link_id = %s OR email = %s", (discord_id, email))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"message": "Discord account or email already registered"}), 400

        # Check if username exists
        cursor.execute("SELECT user_id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({"message": "Username already taken"}), 400

        # Create new user
        user_id = math.floor(random.randint(1000000000, 9999999999))
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        cursor.execute(
            "INSERT INTO users (username, user_password, user_id, email, discord_link_id) VALUES (%s, %s, %s, %s, %s)",
            (username, hashed_password, user_id, email, discord_id)
        )
        cursor.execute(
            "INSERT INTO achievements (user_id) VALUES (%s)",
            (user_id,)
        )
        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({
            "message": "Account created successfully",
            "user_id": user_id
        }), 201

    except Exception as e:
        app.logger.error(f"Discord signup error: {str(e)}")
        return jsonify({"message": "Failed to create account"}), 500

@app.route('/api/math/oauth/discord/verify-2fa', methods=['POST'])
@check_blocked_ip
def verify_discord_2fa():
    """Verify 2FA code for Discord OAuth login"""
    try:
        code = request.headers.get('code')
        user_id = request.headers.get('user-id')
        
        if not code or not user_id:
            return jsonify({"message": "2FA code and user ID are required"}), 400

        conn, cursor = get_db_connection()
        cursor.execute("SELECT secret FROM mfa WHERE user_id = %s", (user_id,))
        mfa_record = cursor.fetchone()

        if not mfa_record:
            cursor.close()
            conn.close()
            return jsonify({"message": "2FA not enabled for this account"}), 400

        secret = fernet.decrypt(mfa_record['secret'].encode()).decode()
        totp = pyotp.TOTP(secret)

        if not totp.verify(code):
            cursor.close()
            conn.close()
            return jsonify({"message": "Invalid 2FA code"}), 400

        # Get user info
        cursor.execute("""
            SELECT u.points, a.moderator 
            FROM users u
            LEFT JOIN achievements a ON u.user_id = a.user_id
            WHERE u.user_id = %s
        """, (user_id,))
        user_info = cursor.fetchone()

        # Generate session token
        token = generate_token(user_id)

        cursor.close()
        conn.close()

        try:
            decrypted_token = fernet.decrypt(token.encode()).decode()
        except InvalidToken:
            return jsonify({"message": "Failed to generate secure token"}), 500

        return jsonify({
            "message": "Successfully authenticated",
            "user_id": user_id,
            "points": user_info['points'],
            "is_mod": bool(user_info['moderator']),
            "session_token": decrypted_token,
            "encrypted_token": token,
            "mfa_enabled": True
        }), 200

    except Exception as e:
        app.logger.error(f"Discord 2FA verification error: {str(e)}")
        return jsonify({"message": "Authentication failed"}), 500

@app.route('/api/math/oauth/discord/link/start', methods=['GET'])
@check_blocked_ip
@require_token
def start_discord_link():
    """Start the Discord OAuth flow for linking an account"""
    user_id = request.headers.get('user-id')
    if not user_id:
        return jsonify({"message": "User ID is required"}), 400

    # Store the user_id in session for the callback
    session['linking_user_id'] = user_id
    
    # Generate Discord OAuth URL
    oauth_url = f'https://discord.com/api/oauth2/authorize?client_id={CLIENT_ID}&redirect_uri={quote(REDIRECT_URI2)}&response_type=code&scope=identify%20email'
    return jsonify({"authorization_url": oauth_url}), 200

@app.route('/api/math/oauth/discord/link/callback', methods=['GET'])
@check_blocked_ip
def discord_link_callback():
    """Handle the Discord OAuth callback for account linking"""
    try:
        # Get the user_id from session
        user_id = session.get('linking_user_id')
        if not user_id:
            return jsonify({"message": "No user ID found in session"}), 400

        # Get the authorization code from the callback
        code = request.args.get('code')
        app.logger.warn(f"Authorization code received: {code}")
        if not code:
            return jsonify({"message": "No authorization code received"}), 400
        
        token_data = exchange_code(code, REDIRECT_URI2)  # Use REDIRECT_URI2 for linking
        access_token = token_data['access_token']

        # Get user info from Discord
        headers = {
            'Authorization': f'Bearer {access_token}'
        }
        user_response = requests.get(f'{API_ENDPOINT}/users/@me', headers=headers)
        user_response.raise_for_status()
        user_data = user_response.json()

        discord_id = user_data.get('id')
        if not discord_id:
            return jsonify({"message": "Could not get Discord user ID"}), 400

        # Check if the Discord account is already linked to another user
        conn, cursor = get_db_connection()
        cursor.execute("SELECT user_id FROM users WHERE discord_link_id = %s AND user_id != %s", (discord_id, user_id))
        existing_link = cursor.fetchone()

        if existing_link:
            cursor.close()
            conn.close()
            return jsonify({"message": "This Discord account is already linked to another user"}), 400

        # Update the user's Discord link ID
        cursor.execute("UPDATE users SET discord_link_id = %s WHERE user_id = %s", (discord_id, user_id))
        conn.commit()
        cursor.close()
        conn.close()

        # Clear the session
        session.pop('linking_user_id', None)

        # Redirect to settings page with success message
        return redirect('/math/settings.html?message=Discord account linked successfully')

    except Exception as e:
        app.logger.error(f"Discord account linking error: {str(e)}")
        return jsonify({"message": "Failed to link Discord account"}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3001, debug=True)