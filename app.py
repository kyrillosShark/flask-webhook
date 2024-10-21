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
from flask import Flask, request, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS

from twilio.rest import Client
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from bson import BSON  # From pymongo
from dotenv import load_dotenv

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

# Database Configuration using DATABASE_URL
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_EXPIRE_ON_COMMIT'] = False  # Prevents DetachedInstanceError
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

# ----------------------------
# Database Models
# ----------------------------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=False, nullable=False)
    phone_number = db.Column(db.String(20), unique=False, nullable=False)
    membership_start = db.Column(db.DateTime, nullable=False)
    membership_end = db.Column(db.DateTime, nullable=False)

    def is_membership_active(self):
        now = datetime.datetime.utcnow()
        return self.membership_start <= now <= self.membership_end

class UnlockToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(36), unique=False, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('unlock_tokens', lazy=True))

    def is_valid(self):
        now = datetime.datetime.utcnow()
        return not self.used and now < self.expires_at and self.user.is_membership_active()

# ----------------------------
# Helper Functions
# ----------------------------

def get_access_token(base_address, instance_name, username, password):
    """
    Authenticates with the Keep by Feenics API and retrieves an access token.

    Returns:
        tuple: (access_token, instance_id)
    """
    token_endpoint = f"{base_address}/token"

    payload = {
        "grant_type": "password",
        "client_id": "consoleApp",
        "client_secret": "consoleSecret",
        "username": username,
        "password": password,
        "instance": instance_name,
        "sendonetimepassword": "false",
        "undefined": ""
    }

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    body_encoded = "&".join([f"{key}={value}" for key, value in payload.items()])

    try:
        response = SESSION.post(token_endpoint, headers=headers, data=body_encoded)
        response.raise_for_status()

        response_data = response.json()
        access_token = response_data.get("access_token")
        instance_id = response_data.get("instance")

        if not access_token or not instance_id:
            raise Exception("Access token or instance ID not found in the response.")

        logger.info("CRM login successful.")
        return access_token, instance_id
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error during CRM login: {http_err}")
        logger.error(f"Response Content: {response.text}")
        raise
    except Exception as err:
        logger.error(f"Error during CRM login: {err}")
        raise

def get_doors(base_address, access_token, instance_id):
    """
    Retrieves a list of available Doors.

    Returns:
        list: List of door objects.
    """
    doors_endpoint = f"{base_address}/api/f/{instance_id}/doors"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.get(doors_endpoint, headers=headers)
        response.raise_for_status()
        doors = response.json()
        logger.info(f"Retrieved {len(doors)} doors.")
        return doors
    except Exception as err:
        logger.error(f"Error retrieving doors: {err}")
        raise

def generate_unlock_token(user_id):
    """
    Generates a unique unlock token for the user and saves it to the database.
    """
    token_str = str(uuid.uuid4())
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)  # Token valid for 15 minutes

    with app.app_context():
        user = User.query.get(user_id)
        if not user:
            logger.error(f"User with ID {user_id} not found.")
            return None

        unlock_token = UnlockToken(
            token=token_str,
            user_id=user.id,
            expires_at=expires_at
        )
        db.session.add(unlock_token)
        db.session.commit()

    logger.info(f"Generated unlock token for user {user.id}: {token_str}")
    return token_str

def create_unlock_link(token):
    """
    Creates an unlock link using the provided token.
    """
    unlock_link = f"{UNLOCK_LINK_BASE_URL}?token={token}"
    logger.info(f"Created unlock link: {unlock_link}")
    return unlock_link

def send_sms(phone_number, unlock_link):
    """
    Sends an SMS message with the unlock link to the specified phone number.
    """
    message_body = f"Your unlock link: {unlock_link}"

    try:
        logger.info(f"Attempting to send SMS to {phone_number}")
        message = client.messages.create(
            body=message_body,
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        logger.info(f"SMS sent to {phone_number}. SID: {message.sid}, Status: {message.status}")
    except Exception as e:
        logger.error(f"Failed to send SMS to {phone_number}: {e}")
        if hasattr(e, 'code'):
            logger.error(f"Twilio Error Code: {e.code}")
        if hasattr(e, 'msg'):
            logger.error(f"Twilio Error Message: {e.msg}")

def unlock_door(user):
    """
    Sends a command to unlock the door for 5 seconds, including user's information in the event data.
    """
    try:
        with app.app_context():
            # Step 1: Authenticate
            access_token, instance_id = get_access_token(
                base_address=BASE_ADDRESS,
                instance_name=INSTANCE_NAME,
                username=KEEP_USERNAME,
                password=KEEP_PASSWORD
            )

            # Step 2: Retrieve Doors
            doors = get_doors(BASE_ADDRESS, access_token, instance_id)
            if not doors:
                logger.error("No doors found.")
                return

            # Select the door to unlock (modify as needed)
            door = doors[0]
            logger.info(f"Selected Door: {door.get('CommonName')}")

            # Step 3: Send Unlock Door Command
            success = send_unlock_door_command(
                base_address=BASE_ADDRESS,
                access_token=access_token,
                instance_id=instance_id,
                door=door,
                duration_seconds=5,
                user=user
            )

            if success:
                logger.info("Door unlock command sent successfully.")
            else:
                logger.error("Door unlock command failed.")

    except Exception as e:
        logger.exception(f"Error in unlocking door: {e}")

def send_unlock_door_command(base_address, access_token, instance_id, door, duration_seconds, user):
    """
    Sends a door unlock command to the specified door, including user's information in the event data.

    Returns:
        bool: True if successful, False otherwise.
    """
    event_endpoint = f"{base_address}/api/f/{instance_id}/eventmessagesink"

    # Prepare EventData with user's information
    event_data = {
        "Duration": duration_seconds,
        "UserFirstName": user.first_name,
        "UserLastName": user.last_name,
        "UserEmail": user.email,
        "UserPhone": user.phone_number
    }

    logger.info(f"Event Data before encoding: {event_data}")

    # Convert EventData to BSON and then to Base64
    try:
        event_data_bson = BSON.encode(event_data)
        event_data_base64 = base64.b64encode(event_data_bson).decode('utf-8')
    except Exception as e:
        logger.error(f"Error encoding EventData: {e}")
        return False

    logger.info(f"EventDataBsonBase64: {event_data_base64}")

    # Construct the payload
    payload = {
        "$type": "Feenics.Keep.WebApi.Model.EventMessagePosting, Feenics.Keep.WebApi.Model",
        "OccurredOn": datetime.datetime.now(timezone.utc).isoformat(),
        "AppKey": "MercuryCommands",
        "EventTypeMoniker": {
            "$type": "Feenics.Keep.WebApi.Model.MonikerItem, Feenics.Keep.WebApi.Model",
            "Namespace": "MercuryServiceCommands",
            "Nickname": "mercury:command-unlockDoor"
        },
        "RelatedObjects": [
            {
                "$type": "Feenics.Keep.WebApi.Model.ObjectLinkItem, Feenics.Keep.WebApi.Model",
                "Href": door['Href'],
                "LinkedObjectKey": door['Key'],
                "CommonName": door['CommonName'],
                "Relation": "Door",
                "MetaDataBson": None
            }
        ],
        "EventDataBsonBase64": event_data_base64
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.post(event_endpoint, headers=headers, json=payload)
        response.raise_for_status()
        logger.info("Door unlock event published successfully.")
        return True
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error during event publishing: {http_err}")
        logger.error(f"Response Content: {response.text}")
        return False
    except Exception as err:
        logger.error(f"Error during event publishing: {err}")
        return False

# ----------------------------
# User Creation and Messaging Workflow
# ----------------------------

def process_user_creation(first_name, last_name, email, phone_number, membership_duration_hours=24):
    """
    Complete workflow to create a user in the local database, generate unlock link, and send an SMS.
    """
    try:
        with app.app_context():
            # Create User in local database
            membership_start = datetime.datetime.utcnow()
            membership_end = membership_start + timedelta(hours=membership_duration_hours)

            user = User(
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone_number=phone_number,
                membership_start=membership_start,
                membership_end=membership_end
            )

            db.session.add(user)
            db.session.commit()
            logger.info(f"User '{first_name} {last_name}' created successfully with ID: {user.id}")

            # Generate Unlock Token and Link
            unlock_token_str = generate_unlock_token(user.id)
            unlock_link = create_unlock_link(unlock_token_str)

            # **Log the Unlock URL for Testing**
            logger.info(f"Unlock URL for testing: {unlock_link}")

            # Send SMS with Unlock Link
            send_sms(phone_number, unlock_link)

    except Exception as e:
        logger.exception(f"Error in processing user creation: {e}")

# ----------------------------
# Unlock Token Management
# ----------------------------

def validate_unlock_token(token):
    """
    Validates the unlock token.
    """
    with app.app_context():
        unlock_token = UnlockToken.query.filter_by(token=token).first()

        if not unlock_token:
            return False, "Invalid token."

        if unlock_token.used:
            return False, "Token has already been used."

        if datetime.datetime.utcnow() >= unlock_token.expires_at:
            return False, "Token has expired."

        if not unlock_token.user.is_membership_active():
            return False, "Membership is no longer active."

        return True, unlock_token

# ----------------------------
# Flask Routes
# ----------------------------

@app.route('/reset_database', methods=['POST'])
def reset_database():
    if not app.config['DEBUG']:
        abort(403, description="Forbidden")

    try:
        db.drop_all()
        db.create_all()
        logger.info("Database reset successfully.")
        return jsonify({'status': 'Database reset successfully'}), 200
    except Exception as e:
        logger.exception(f"Error resetting database: {e}")
        return jsonify({'error': 'Failed to reset database'}), 500

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    data = request.json
    logger.info(f"Received webhook data: {data}")

    # Extract fields from the data
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    email = data.get('email')
    phone_number = data.get('phone')

    # Check for required fields
    if not all([first_name, last_name, email, phone_number]):
        logger.warning("Missing required fields.")
        return jsonify({'error': 'Missing required fields.'}), 400

    logger.info(f"Processing user: {first_name} {last_name}, Email: {email}, Phone: {phone_number}")

    # Process user creation in a separate thread to avoid blocking
    threading.Thread(target=process_user_creation, args=(
        first_name, last_name, email, phone_number)).start()

    return jsonify({'status': 'User creation in progress'}), 200

@app.route('/unlock', methods=['GET'])
def handle_unlock():
    token = request.args.get('token')

    if not token:
        logger.warning("Unlock attempt without token.")
        return jsonify({'error': 'Token is missing'}), 400

    is_valid, result = validate_unlock_token(token)

    if not is_valid:
        logger.warning(f"Invalid unlock token: {result}")
        return jsonify({'error': result}), 400

    unlock_token = result

    with app.app_context():
        unlock_token.used = True
        db.session.commit()

    user = unlock_token.user

    logger.info(f"Unlocking door for user: {user.first_name} {user.last_name}, Email: {user.email}, Phone: {user.phone_number}")

    # Unlock the door in a separate thread to avoid blocking
    threading.Thread(target=unlock_door, args=(user,)).start()

    return jsonify({'message': 'Door is unlocking. Please wait...'}), 200

@app.route('/test_send_unlock_sms', methods=['GET'])
def test_send_unlock_sms():
    """
    Test route to create a test user and send an unlock link via SMS.
    """
    try:
        with app.app_context():
            # Step 1: Create a Test User
            first_name = "Test"
            last_name = "User"
            email = f"test.user{random.randint(1000,9999)}@example.com"
            phone_number = "+1234567890"  # Use a valid test number
            membership_duration_hours = 24  # 24-hour membership for testing

            # Step 2: Create the user in the local database
            membership_start = datetime.datetime.utcnow()
            membership_end = membership_start + timedelta(hours=membership_duration_hours)

            user = User(
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone_number=phone_number,
                membership_start=membership_start,
                membership_end=membership_end
            )

            db.session.add(user)
            db.session.commit()
            logger.info(f"Test User '{first_name} {last_name}' created successfully with ID: {user.id}")

            # Step 3: Generate Unlock Token and Link
            unlock_token_str = generate_unlock_token(user.id)
            unlock_link = create_unlock_link(unlock_token_str)

            # **Log the Unlock URL for Testing**
            logger.info(f"Unlock URL for testing: {unlock_link}")

            # Step 4: Send SMS with Unlock Link
            send_sms(phone_number, unlock_link)

        logger.info(f"Test unlock link SMS sent successfully to {phone_number}")
        return jsonify({
            'status': 'Test unlock link SMS sent successfully',
            'email': email,
            'phone_number': phone_number,
            'unlock_link': unlock_link
        }), 200

    except Exception as e:
        logger.exception(f"Error in test_send_unlock_sms: {e}")
        return jsonify({'error': 'Failed to send test unlock SMS'}), 500

# ----------------------------
# Main Execution
# ----------------------------

if __name__ == "__main__":
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000)
