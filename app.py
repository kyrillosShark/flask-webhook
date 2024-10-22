import os
import sys
import json
import uuid
import base64
import logging
import threading
import datetime
from datetime import timezone, timedelta
import re
import random  # Ensure random is imported
from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS

from twilio.rest import Client
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Ensure `bson` is installed. If not, install it using `pip install bson`
import bson
from bson import BSON

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

# Initialize Limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["100 per day", "10 per hour"]
)

limiter.init_app(app)

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
    token = db.Column(db.String(36), unique=True, nullable=False)  # Ensure tokens are unique
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

    user = db.relationship('User', backref=db.backref('unlock_tokens', lazy=True))

    def is_valid(self):
        now = datetime.datetime.utcnow()
        return now < self.expires_at and self.user.is_membership_active()

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
    """
    doors_endpoint = f"{base_address}/api/f/{instance_id}/Doors?$top=100"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }

    try:
        response = SESSION.get(doors_endpoint, headers=headers)
        response.raise_for_status()
        doors = response.json()
        logger.info(f"Retrieved doors: {doors}")
        doors = doors.get('value', doors)
        return doors
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error occurred while retrieving doors: {http_err}")
        logger.error(f"Response Status Code: {response.status_code}")
        logger.error(f"Response Content: {response.text}")
        return []
    except Exception as err:
        logger.error(f"Error retrieving doors: {err}")
        return []

def generate_unlock_token(user_id):
    """
    Generates a unique unlock token for the user and saves it to the database.
    """
    token_str = str(uuid.uuid4())
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=24)  # Token valid for 24 hours

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
    unlock_link = f"{UNLOCK_LINK_BASE_URL}/unlock?token={token}"
    logger.info(f"Created unlock link: {unlock_link}")
    return unlock_link

def send_sms(phone_number, unlock_link):
    """
    Sends an SMS message with the unlock link to the specified phone number.
    """
    message_body = f"Welcome! Use this link to unlock the door: {unlock_link}\nClick the 'Unlock' button on the page. This link is valid for 24 hours."

    try:
        logger.info(f"Attempting to send SMS to {phone_number}")
        logger.info(f"Unlock link sent: {unlock_link}")  # Log the URL
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

def unlock_door(user, duration_seconds=3):
    """
    Simulates a card read for the user to unlock the door.
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

            # Step 2: Create Person
            person = create_person(BASE_ADDRESS, access_token, instance_id, user)

            if not person:
                logger.error("Failed to create person.")
                return

            # Step 3: Assign Card to Person
            card_assignment = assign_card_to_person(BASE_ADDRESS, access_token, instance_id, person)

            if not card_assignment:
                logger.error("Failed to assign card to person.")
                return

            # Step 4: Simulate Card Read
            success = simulate_card_read(
                base_address=BASE_ADDRESS,
                access_token=access_token,
                instance_id=instance_id,
                card_assignment=card_assignment,
                user=user
            )

            if success:
                logger.info("Card read simulated successfully.")
            else:
                logger.error("Failed to simulate card read.")

    except Exception as e:
        logger.exception(f"Error in unlocking door: {e}")

def create_person(base_address, access_token, instance_id, user):
    """
    Creates a new person in the Keep by Feenics system.
    """
    person_endpoint = f"{base_address}/api/f/{instance_id}/People"

    payload = {
        "GivenName": user.first_name,
        "Surname": user.last_name,
        "CommonName": f"{user.first_name} {user.last_name}",
        "Addresses": [
            {
                "$type": "Feenics.Keep.WebApi.Model.EmailAddressInfo, Feenics.Keep.WebApi.Model",
                "MailTo": user.email,
                "Type": "Work"
            },
            {
                "$type": "Feenics.Keep.WebApi.Model.PhoneInfo, Feenics.Keep.WebApi.Model",
                "Number": user.phone_number,
                "Type": "Mobile"
            }
        ]
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        response = SESSION.post(person_endpoint, headers=headers, json=payload)
        response.raise_for_status()
        person = response.json()
        logger.info(f"Created person: {person}")
        return person
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error during person creation: {http_err}")
        logger.error(f"Response Status Code: {response.status_code}")
        logger.error(f"Response Content: {response.text}")
        return None
    except Exception as err:
        logger.error(f"Error during person creation: {err}")
        return None

def assign_card_to_person(base_address, access_token, instance_id, person):
    """
    Assigns a card to the person using HID 26-bit format with facility code 111.
    """
    cards_endpoint = f"{base_address}/api/f/{instance_id}/People/{person['Key']}/Cards"

    # Generate a unique card number in the range 0 to 65,535
    card_number = generate_unique_card_number(base_address, access_token, instance_id)

    # Facility code is set to 111
    facility_code = 111

    payload = {
        "$type": "Feenics.Keep.WebApi.Model.CardAssignmentInfo, Feenics.Keep.WebApi.Model",
        "Key": None,
        "EncodedCardNumber": card_number,
        "DisplayCardNumber": str(card_number),
        "FacilityCode": facility_code,
        "ActiveOn": datetime.datetime.utcnow().isoformat() + "Z",
        "ExpiresOn": (datetime.datetime.utcnow() + timedelta(days=365)).isoformat() + "Z",
        "PinCode": None,
        "AntiPassbackExempt": False,
        "ExtendedAccess": False,
        "PinExempt": False,
        "IsDisabled": False,
        "ManagerLevel": 0,
        "OriginalUseCount": None,
        "CurrentUseCount": 0,
        "Note": None,
        "HexValue": None,
        "RecordId": None,
        "LastUsed": None,
        "Href": None
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        response = SESSION.post(cards_endpoint, headers=headers, json=payload)
        response.raise_for_status()
        card_assignment = response.json()
        logger.info(f"Assigned card to person: {card_assignment}")
        return card_assignment
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error during card assignment: {http_err}")
        logger.error(f"Response Status Code: {response.status_code}")
        logger.error(f"Response Content: {response.text}")
        if response.status_code == 400:
            logger.error(f"Bad Request: {response.json()}")
        return None
    except Exception as err:
        logger.error(f"Error during card assignment: {err}")
        return None

def generate_unique_card_number(base_address, access_token, instance_id):
    """
    Generates a valid and unique card number (0 to 65,535).
    """
    min_value = 0
    max_value = 65535

    while True:
        card_number = random.randint(min_value, max_value)
        if is_card_number_unique(base_address, access_token, instance_id, card_number):
            logger.info(f"Generated unique card number: {card_number}")
            return card_number

def is_card_number_unique(base_address, access_token, instance_id, card_number):
    """
    Checks if the card number with facility code is already assigned.
    """
    facility_code = 111  # Use the same facility code
    filter_query = f"EncodedCardNumber eq {card_number} and FacilityCode eq {facility_code}"
    encoded_filter_query = quote_plus(filter_query)
    endpoint = f"{base_address}/api/f/{instance_id}/cards?$filter={encoded_filter_query}"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json"
    }
    try:
        response = SESSION.get(endpoint, headers=headers)
        response.raise_for_status()
        cards = response.json().get('value', [])
        is_unique = len(cards) == 0
        logger.info(f"Card number {card_number} with facility code {facility_code} is {'unique' if is_unique else 'not unique'}")
        return is_unique
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error during card number uniqueness check: {http_err}")
        logger.error(f"Response Status Code: {response.status_code}")
        logger.error(f"Response Content: {response.text}")
        # Return False to avoid assigning potentially duplicate card numbers
        return False
    except Exception as e:
        logger.error(f"Error checking card number uniqueness: {e}")
        # Return False to avoid assigning potentially duplicate card numbers
        return False

def simulate_card_read(base_address, access_token, instance_id, card_assignment, user):
    """
    Simulates a card read at a specific reader.
    """
    # You need to specify the Controller, Reader, and CardFormat keys.
    # Replace the placeholders below with actual keys from your system.

    controller_key = "YOUR_CONTROLLER_KEY"
    reader_key = "YOUR_READER_KEY"
    card_format_key = "YOUR_CARD_FORMAT_KEY"

    event_endpoint = f"{base_address}/api/f/{instance_id}/eventmessagesink"

    # Prepare EventDataBsonBase64
    event_data = {
        "Reason": "Simulated card read",
        "FacilityCode": card_assignment.get('FacilityCode', 0),
        "EncodedCardNumber": card_assignment['EncodedCardNumber']
    }
    event_data_bson = BSON.encode(event_data)
    event_data_b64 = base64.b64encode(event_data_bson).decode('utf-8')

    payload = {
        "$type": "Feenics.Keep.WebApi.Model.EventMessagePosting, Feenics.Keep.WebApi.Model",
        "OccurredOn": datetime.datetime.utcnow().isoformat() + "Z",
        "AppKey": "MercuryCommands",
        "EventTypeMoniker": {
            "$type": "Feenics.Keep.WebApi.Model.MonikerItem, Feenics.Keep.WebApi.Model",
            "Namespace": "MercuryServiceCommands",
            "Nickname": "mercury:command-simulateCardRead"
        },
        "RelatedObjects": [
            {
                "$type": "Feenics.Keep.WebApi.Model.ObjectLinkItem, Feenics.Keep.WebApi.Model",
                "Href": f"/api/f/{instance_id}/Readers/{reader_key}",
                "LinkedObjectKey": reader_key,
                "CommonName": "Reader",
                "Relation": "Reader",
                "MetaDataBson": None
            },
            {
                "$type": "Feenics.Keep.WebApi.Model.ObjectLinkItem, Feenics.Keep.WebApi.Model",
                "Href": f"/api/f/{instance_id}/CardFormats/{card_format_key}",
                "LinkedObjectKey": card_format_key,
                "CommonName": "CardFormat",
                "Relation": "CardFormat",
                "MetaDataBson": None
            },
            {
                "$type": "Feenics.Keep.WebApi.Model.ObjectLinkItem, Feenics.Keep.WebApi.Model",
                "Href": f"/api/f/{instance_id}/Controllers/{controller_key}",
                "LinkedObjectKey": controller_key,
                "CommonName": "Controller",
                "Relation": "Controller",
                "MetaDataBson": None
            }
        ],
        "EventDataBsonBase64": event_data_b64
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    try:
        response = SESSION.post(event_endpoint, headers=headers, json=payload)
        response.raise_for_status()
        logger.info("Simulated card read event published successfully.")
        return True
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error during card read simulation: {http_err}")
        logger.error(f"Response Status Code: {response.status_code}")
        logger.error(f"Response Content: {response.text}")
        return False
    except Exception as err:
        logger.error(f"Error during card read simulation: {err}")
        return False

def is_valid_email(email):
    """
    Validates the email format.
    """
    regex = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    return re.match(regex, email)

def is_valid_phone(phone):
    """
    Validates the phone number format (simple validation).
    """
    regex = r'^\+\d{10,15}$'
    return re.match(regex, phone)

def validate_unlock_token(token):
    """
    Validates the unlock token.
    """
    with app.app_context():
        unlock_token = UnlockToken.query.filter_by(token=token).first()

        if not unlock_token:
            return False, "Invalid token."

        if datetime.datetime.utcnow() >= unlock_token.expires_at:
            return False, "Token has expired."

        if not unlock_token.user.is_membership_active():
            return False, "Membership is no longer active."

        return True, unlock_token

# ----------------------------
# Flask Routes
# ----------------------------

@app.route('/')
def index():
    return "Flask app is running!"

@app.route('/generate_token', methods=['POST'])
@limiter.limit("5 per minute")  # Adjust rate limit as needed
def generate_token():
    """
    Endpoint to generate a temporary unlock token for a user.
    Expects JSON data with first_name, last_name, email, and phone.
    Returns the generated token and unlock link in JSON response.
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
            # Check if user already exists
            user = User.query.filter_by(email=email).first()
            if not user:
                # Create a new user if not exists
                membership_start = datetime.datetime.utcnow()
                membership_end = membership_start + timedelta(hours=24)  # 24-hour validity

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
                logger.info(f"Created new user '{first_name} {last_name}' with ID: {user.id}")
            else:
                # Update membership_end if necessary
                new_end = datetime.datetime.utcnow() + timedelta(hours=24)
                if user.membership_end < new_end:
                    user.membership_end = new_end
                    db.session.commit()
                    logger.info(f"Extended membership for existing user '{user.email}'")

            # Generate Unlock Token and Link
            unlock_token_str = generate_unlock_token(user.id)
            if not unlock_token_str:
                logger.error("Failed to generate unlock token.")
                return jsonify({'error': 'Failed to generate unlock token.'}), 500

            # Create the unlock link
            unlock_link = create_unlock_link(unlock_token_str)

            # Send SMS with Unlock Link
            send_sms(phone_number, unlock_link)

            # Return the token and unlock link in the response
            return jsonify({'token': unlock_token_str, 'unlock_link': unlock_link}), 200

    except Exception as e:
        logger.exception(f"Error in generating token: {e}")
        return jsonify({'error': 'Internal server error.'}), 500

@app.route('/unlock', methods=['GET', 'POST'])
def handle_unlock():
    if request.method == 'GET':
        token = request.args.get('token')

        if not token:
            logger.warning("Unlock attempt without token.")
            return jsonify({'error': 'Token is missing'}), 400

        is_valid, result = validate_unlock_token(token)

        if not is_valid:
            logger.warning(f"Invalid unlock token: {result}")
            return jsonify({'error': result}), 400

        unlock_token = result

        # Render the unlock page with the unlock button
        return render_template('unlock.html', token=token)

    elif request.method == 'POST':
        # Handle the form submission when the unlock button is clicked
        token = request.form.get('token')
        if not token:
            logger.warning("Unlock attempt without token in form.")
            return jsonify({'error': 'Token is missing in form submission'}), 400

        is_valid, result = validate_unlock_token(token)

        if not is_valid:
            logger.warning(f"Invalid unlock token: {result}")
            return jsonify({'error': result}), 400

        unlock_token = result

        user = unlock_token.user

        logger.info(f"Unlocking door for user: {user.first_name} {user.last_name}, Email: {user.email}, Phone: {user.phone_number}")

        # Unlock the door by simulating a card read
        threading.Thread(target=unlock_door, args=(user, 3)).start()  # Duration is not used in this context

        # Render a success page or message
        return render_template('unlock.html', message='Simulating card read. Please wait...')

# ----------------------------
# Main Execution
# ----------------------------

if __name__ == "__main__":
    # Run the Flask app
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
