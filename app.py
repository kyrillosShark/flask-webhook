import os
import sys
import json
import uuid
import base64
import logging
import threading
import datetime
from datetime import timezone, timedelta
import random
import re
from flask import Flask, request, jsonify, abort, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS

from twilio.rest import Client
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from bson import BSON  # From pymongo
from dotenv import load_dotenv

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

load_dotenv()

# ----------------------------
# Configuration and Setup
# ----------------------------

app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)
app.config['DEBUG'] = True

# Environment Variables
BASE_ADDRESS = os.getenv("BASE_ADDRESS")
INSTANCE_NAME = os.getenv("INSTANCE_NAME")
KEEP_USERNAME = os.getenv("KEEP_USERNAME")
KEEP_PASSWORD = os.getenv("KEEP_PASSWORD")
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")
UNLOCK_LINK_BASE_URL = os.getenv("UNLOCK_LINK_BASE_URL")
DATABASE_URL = os.getenv("DATABASE_URL")

# Check for required environment variables
required_env_vars = [
    'BASE_ADDRESS', 'INSTANCE_NAME', 'KEEP_USERNAME', 'KEEP_PASSWORD',
    'TWILIO_ACCOUNT_SID', 'TWILIO_AUTH_TOKEN', 'TWILIO_PHONE_NUMBER',
    'UNLOCK_LINK_BASE_URL', 'DATABASE_URL'
]

loaded_vars = {
    'BASE_ADDRESS': BASE_ADDRESS,
    'INSTANCE_NAME': INSTANCE_NAME,
    'KEEP_USERNAME': KEEP_USERNAME,
    'KEEP_PASSWORD': KEEP_PASSWORD,
    'TWILIO_ACCOUNT_SID': TWILIO_ACCOUNT_SID,
    'TWILIO_AUTH_TOKEN': TWILIO_AUTH_TOKEN,
    'TWILIO_PHONE_NUMBER': TWILIO_PHONE_NUMBER,
    'UNLOCK_LINK_BASE_URL': UNLOCK_LINK_BASE_URL,
    'DATABASE_URL': DATABASE_URL
}

missing_env_vars = [var for var, value in loaded_vars.items() if not value]
if missing_env_vars:
    logger.error(f"Missing environment variables: {', '.join(missing_env_vars)}")
    sys.exit(1)

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_EXPIRE_ON_COMMIT'] = False
db = SQLAlchemy(app)

# Initialize Flask-Migrate
migrate = Migrate(app, db)

# Initialize Twilio Client
client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

# Session with Retry Strategy
def create_session():
    session = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST", "PUT"]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('https://', adapter)
    session.mount('http://', adapter)
    return session

SESSION = create_session()

# Initialize Limiter
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per day", "10 per hour"]
)

# ----------------------------
# Database Models
# ----------------------------

# [Your database models remain unchanged]

# ----------------------------
# Helper Functions
# ----------------------------

# [Your helper functions remain unchanged]

# ----------------------------
# Flask Routes
# ----------------------------

@app.route('/generate_token', methods=['POST'])
@limiter.limit("5 per minute")  # Adjust rate limit as needed
def generate_token():
    """
    Endpoint to generate a temporary unlock token for a user.
    Expects JSON data with first_name, last_name, email, and phone.
    Returns the generated token in JSON response.
    """
    data = request.json
    logger.info(f"Received token generation request from {request.remote_addr}: {data}")

    # Extract fields from the data
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    phone_number = data.get('phone')

    # Validate required fields
    if not all([first_name, last_name, email, phone_number]):
        logger.warning("Missing required fields for token generation.")
        return jsonify({'error': 'Missing required fields: first_name, last_name, email, phone'}), 400

    # Validate email and phone format
    if not is_valid_email(email):
        logger.warning("Invalid email format.")
        return jsonify({'error': 'Invalid email format.'}), 400

    if not is_valid_phone(phone_number):
        logger.warning("Invalid phone number format.")
        return jsonify({'error': 'Invalid phone number format. Use + followed by country code and number.'}), 400

    try:
        with app.app_context():
            # [User creation and token generation logic remains the same]
            # ...

            # Return the token in the response
            return jsonify({'token': unlock_token_str}), 200

    except Exception as e:
        logger.exception(f"Error in generating token: {e}")
        return jsonify({'error': 'Internal server error.'}), 500

# [Other routes remain unchanged]

# ----------------------------
# Main Execution
# ----------------------------

if __name__ == "__main__":
    # Run the Flask app
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
