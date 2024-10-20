from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import logging
import threading
import uuid
import datetime
from datetime import timezone, timedelta
from twilio.rest import Client
import requests
import json
import base64
import sys
import random
from bson import BSON  # From pymongo
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv
load_dotenv()

# ----------------------------
# Configuration and Setup
# ----------------------------

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

# Environment Variables
BASE_ADDRESS = os.getenv("BASE_ADDRESS")
INSTANCE_NAME = os.getenv("INSTANCE_NAME")
KEEP_USERNAME = os.getenv("KEEP_USERNAME")
KEEP_PASSWORD = os.getenv("KEEP_PASSWORD")
BADGE_TYPE_NAME = os.getenv("BADGE_TYPE_NAME", "Employee Badge")
SIMULATION_REASON = os.getenv("SIMULATION_REASON", "Automated Testing of Card Read")
FACILITY_CODE = int(os.getenv("FACILITY_CODE", 100))
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
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"]
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
    given_name = db.Column(db.String(50), nullable=False)
    surname = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=False, nullable=False)
    phone_number = db.Column(db.String(20), unique=False, nullable=False)
    card_number = db.Column(db.String(20), unique=False, nullable=False)
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

def get_badge_types(base_address, access_token, instance_id):
    """
    Retrieves a list of available Badge Types.
    """
    get_badge_types_endpoint = f"{base_address}/api/f/{instance_id}/badgetypes"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.get(get_badge_types_endpoint, headers=headers)
        response.raise_for_status()

        badge_types = response.json()
        return badge_types
    except Exception as err:
        logger.error(f"Error retrieving badge types: {err}")
        raise

def create_badge_type(base_address, access_token, instance_id, badge_type_name):
    """
    Creates a new Badge Type in the Keep by Feenics system.

    Returns:
        dict: Details of the created Badge Type.
    """
    create_badge_endpoint = f"{base_address}/api/f/{instance_id}/badgetypes"

    badge_type_data = {
        "CommonName": badge_type_name,
        "Description": f"{badge_type_name} Description"
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.post(create_badge_endpoint, headers=headers, json=badge_type_data)
        response.raise_for_status()

        response_data = response.json()
        badge_type_id = response_data.get("Key")

        if not badge_type_id:
            raise Exception("Badge Type ID not found in the response.")

        logger.info(f"Badge Type '{badge_type_name}' created successfully with ID: {badge_type_id}")
        return response_data
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 409:
            logger.info(f"Badge Type '{badge_type_name}' already exists.")
            return None
        else:
            logger.error(f"HTTP error during Badge Type creation: {http_err}")
            logger.error(f"Response Content: {response.text}")
            raise
    except Exception as err:
        logger.error(f"Error during Badge Type creation: {err}")
        raise

def get_badge_type_details(base_address, access_token, instance_id, badge_type_name):
    """
    Retrieves details of a specific Badge Type.

    Returns:
        dict: Details of the Badge Type.
    """
    badge_types = get_badge_types(base_address, access_token, instance_id)

    for bt in badge_types:
        if bt.get("CommonName") == badge_type_name:
            return bt

    raise Exception(f"Badge Type '{badge_type_name}' not found after creation.")

def generate_card_number():
    """
    Generates a random 26-bit HID card number.

    Returns:
        int: A 26-bit card number.
    """
    card_number = random.randint(0, 67108863)
    return card_number

def create_user(base_address, access_token, instance_id, given_name, surname, email, phone_number, badge_type_info, membership_duration_hours):
    """
    Creates a new user in the Keep by Feenics system.

    Returns:
        User: The created User object.
    """
    create_person_endpoint = f"{base_address}/api/f/{instance_id}/people"

    card_number = generate_card_number()

    # Prepare the current and expiration times
    active_on = datetime.datetime.utcnow().isoformat()
    expires_on = (datetime.datetime.utcnow() + timedelta(hours=membership_duration_hours)).isoformat()

    user_data = {
        "$type": "Feenics.Keep.WebApi.Model.PersonInfo, Feenics.Keep.WebApi.Model",
        "CommonName": f"{given_name} {surname}",
        "GivenName": given_name,
        "Surname": surname,
        "Addresses": [
            {
                "$type": "Feenics.Keep.WebApi.Model.EmailAddressInfo, Feenics.Keep.WebApi.Model",
                "MailTo": email,
                "Type": "Work"
            },
            {
                "$type": "Feenics.Keep.WebApi.Model.PhoneInfo, Feenics.Keep.WebApi.Model",
                "Number": phone_number,
                "Type": "Mobile"
            }
        ],
        "ObjectLinks": [
            {
                "$type": "Feenics.Keep.WebApi.Model.ObjectLinkItem, Feenics.Keep.WebApi.Model",
                "Relation": "BadgeType",
                "CommonName": badge_type_info.get("CommonName"),
                "Href": badge_type_info.get("Href"),
                "LinkedObjectKey": badge_type_info.get("Key"),
                "MetaDataBson": None
            }
        ],
        "CardAssignments": [
            {
                "$type": "Feenics.Keep.WebApi.Model.CardAssignmentInfo, Feenics.Keep.WebApi.Model",
                "EncodedCardNumber": int(card_number),
                "DisplayCardNumber": str(card_number),
                "ActiveOn": active_on,
                "ExpiresOn": expires_on,
                "AntiPassbackExempt": False,
                "ExtendedAccess": False
            }
        ],
        "Metadata": [
            {
                "$type": "Feenics.Keep.WebApi.Model.MetadataItem, Feenics.Keep.WebApi.Model",
                "Application": "CustomApp",
                "Values": json.dumps({"CardNumber": format(card_number, 'x')}),
                "ShouldPublishUpdateEvents": False
            }
        ]
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.post(create_person_endpoint, headers=headers, json=user_data)
        response.raise_for_status()

        response_data = response.json()
        user_id = response_data.get("Key")

        if not user_id:
            raise Exception("User ID not found in the response.")

        logger.info(f"User '{given_name} {surname}' created successfully with ID: {user_id}")
        logger.info(f"Assigned Card Number: {card_number} (Hex: {format(card_number, 'x')})")

        # Create User in local database
        membership_start = datetime.datetime.utcnow()
        membership_end = membership_start + timedelta(hours=membership_duration_hours)  # Customizable duration

        with app.app_context():
            user = User(
                given_name=given_name,
                surname=surname,
                email=email,
                phone_number=phone_number,
                card_number=str(card_number),
                membership_start=membership_start,
                membership_end=membership_end
            )

            db.session.add(user)
            db.session.commit()

        return user
    except Exception as err:
        logger.error(f"Error during user creation: {err}")
        raise

def get_readers(base_address, access_token, instance_id):
    """
    Retrieves a list of available Readers.

    Returns:
        list: List of reader objects.
    """
    readers_endpoint = f"{base_address}/api/f/{instance_id}/readers"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.get(readers_endpoint, headers=headers)
        response.raise_for_status()
        readers = response.json()
        logger.info(f"Retrieved {len(readers)} readers.")
        return readers
    except Exception as err:
        logger.error(f"Error retrieving readers: {err}")
        raise

def get_card_formats(base_address, access_token, instance_id):
    """
    Retrieves a list of available Card Formats.

    Returns:
        list: List of card format objects.
    """
    card_formats_endpoint = f"{base_address}/api/f/{instance_id}/cardformats"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.get(card_formats_endpoint, headers=headers)
        response.raise_for_status()
        card_formats = response.json()
        logger.info(f"Retrieved {len(card_formats)} card formats.")
        return card_formats
    except Exception as err:
        logger.error(f"Error retrieving card formats: {err}")
        raise

def get_controllers(base_address, access_token, instance_id):
    """
    Retrieves a list of available Controllers.

    Returns:
        list: List of controller objects.
    """
    controllers_endpoint = f"{base_address}/api/f/{instance_id}/controllers"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.get(controllers_endpoint, headers=headers)
        response.raise_for_status()
        controllers = response.json()
        logger.info(f"Retrieved {len(controllers)} controllers.")
        return controllers
    except Exception as err:
        logger.error(f"Error retrieving controllers: {err}")
        raise

def simulate_card_read(base_address, access_token, instance_id, reader, card_format, controller, reason, facility_code, card_number):
    """
    Simulates a card read by publishing a simulateCardRead event.

    Returns:
        bool: True if successful, False otherwise.
    """
    event_endpoint = f"{base_address}/api/f/{instance_id}/eventmessagesink"

    # Convert card_number to hexadecimal string
    encoded_card_number_hex = format(int(card_number), 'x')

    # Construct EventData as a dictionary
    event_data = {
        "Reason": reason,
        "FacilityCode": str(facility_code),
        "EncodedCardNumber": encoded_card_number_hex
    }

    # Convert EventData to BSON and then to Base64
    event_data_bson = BSON.encode(event_data)
    event_data_base64 = base64.b64encode(event_data_bson).decode('utf-8')

    # Construct the payload
    payload = {
        "$type": "Feenics.Keep.WebApi.Model.EventMessagePosting, Feenics.Keep.WebApi.Model",
        "OccurredOn": datetime.datetime.now(timezone.utc).isoformat(),
        "AppKey": "MercuryCommands",
        "EventTypeMoniker": {
            "$type": "Feenics.Keep.WebApi.Model.MonikerItem, Feenics.Keep.WebApi.Model",
            "Namespace": "MercuryServiceCommands",
            "Nickname": "mercury:command-simulateCardRead"
        },
        "RelatedObjects": [
            {
                "$type": "Feenics.Keep.WebApi.Model.ObjectLinkItem, Feenics.Keep.WebApi.Model",
                "Href": reader['Href'],
                "LinkedObjectKey": reader['Key'],
                "CommonName": reader['CommonName'],
                "Relation": "Reader",
                "MetaDataBson": None
            },
            {
                "$type": "Feenics.Keep.WebApi.Model.ObjectLinkItem, Feenics.Keep.WebApi.Model",
                "Href": card_format['Href'],
                "LinkedObjectKey": card_format['Key'],
                "CommonName": card_format['CommonName'],
                "Relation": "CardFormat",
                "MetaDataBson": None
            },
            {
                "$type": "Feenics.Keep.WebApi.Model.ObjectLinkItem, Feenics.Keep.WebApi.Model",
                "Href": controller['Href'],
                "LinkedObjectKey": controller['Key'],
                "CommonName": controller['CommonName'],
                "Relation": "Controller",
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
        logger.info("Card read simulation event published successfully.")
        return True
    except Exception as err:
        logger.error(f"Error during event publishing: {err}")
        return False

def parse_full_name(full_name):
    """
    Splits the full name into given name and surname.
    Assumes the last word is the surname and the rest is the given name.

    Args:
        full_name (str): The full name of the user.

    Returns:
        tuple: (given_name, surname)

    Raises:
        ValueError: If the full name cannot be split properly.
    """
    parts = full_name.strip().split()
    if len(parts) < 2:
        raise ValueError("Full name must contain at least a given name and a surname.")
    given_name = ' '.join(parts[:-1])
    surname = parts[-1]
    return given_name, surname

def generate_unlock_token(user):
    """
    Generates a unique unlock token for the user and saves it to the database.
    """
    token_str = str(uuid.uuid4())
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(minutes=15)  # Token valid for 15 minutes

    with app.app_context():
        unlock_token = UnlockToken(
            token=token_str,
            user_id=user.id,
            expires_at=expires_at
        )
        db.session.add(unlock_token)
        db.session.commit()

    return token_str

def create_unlock_link(token):
    """
    Creates an unlock link using the provided token.
    """
    unlock_link = f"{UNLOCK_LINK_BASE_URL}?token={token}"
    return unlock_link
def send_sms(phone_number, unlock_link):
    """
    Sends an SMS message with the unlock link to the specified phone number.
    """
    message_body = f"Your unlock link: {unlock_link}"

    try:
        message = client.messages.create(
            body=message_body,
            from_=TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        logger.info(f"SMS sent to {phone_number}. SID: {message.sid}")
    except Exception as e:
        logger.error(f"Failed to send SMS to {phone_number}: {e}")


def test_send_sms():
    test_phone_number = "+18777804236"  # Replace with your verified number
    test_unlock_link = "https://your-app-url.com/unlock?token=TESTTOKEN1234"
    send_sms(test_phone_number, test_unlock_link)
test_send_sms()
# ----------------------------
# User Creation and Messaging Workflow
# ----------------------------

def process_user_creation(given_name, surname, email, phone_number, membership_duration_hours=24):
    """
    Complete workflow to create a user in CRM, store membership info, generate unlock link, and send an SMS.
    """
    try:
        # Step 1: Authenticate
        access_token, instance_id = get_access_token(
            base_address=BASE_ADDRESS,
            instance_name=INSTANCE_NAME,
            username=KEEP_USERNAME,
            password=KEEP_PASSWORD
        )

        # Step 2: Get or Create Badge Type
        badge_types = get_badge_types(BASE_ADDRESS, access_token, instance_id)
        badge_type_info = next((bt for bt in badge_types if bt.get("CommonName") == BADGE_TYPE_NAME), None)

        if not badge_type_info:
            logger.info(f"Badge Type '{BADGE_TYPE_NAME}' does not exist. Creating it now.")
            badge_type_response = create_badge_type(BASE_ADDRESS, access_token, instance_id, BADGE_TYPE_NAME)
            if badge_type_response:
                badge_type_info = badge_type_response
            else:
                # If Badge Type already exists (status code 409), retrieve its details
                badge_type_info = get_badge_type_details(BASE_ADDRESS, access_token, instance_id, BADGE_TYPE_NAME)

        # Step 3: Check if user exists in the database
        with app.app_context():
            existing_user = User.query.filter_by(email=email).first()

            if existing_user:
                logger.info(f"User with email {email} already exists.")
                return

            # Create the user via CRM API and store in local database
            user = create_user(
                base_address=BASE_ADDRESS,
                access_token=access_token,
                instance_id=instance_id,
                given_name=given_name,
                surname=surname,
                email=email,
                phone_number=phone_number,
                badge_type_info=badge_type_info,
                membership_duration_hours=membership_duration_hours
            )

        # Step 4: Generate Unlock Token and Link
        unlock_token_str = generate_unlock_token(user)
        unlock_link = create_unlock_link(unlock_token_str)

        # Step 5: Send SMS with Unlock Link
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
        return jsonify({'status': 'Database reset successfully'}), 200
    except Exception as e:
        logger.exception(f"Error resetting database: {e}")
        return jsonify({'error': 'Failed to reset database'}), 500
@app.route('/webhook', methods=['POST'])
def handle_webhook():
    data = request.json
    logger.info(f"Received webhook data: {data}")

    # Initialize variables
    given_name = data.get('given_name')
    surname = data.get('surname')

    # If given_name or surname is missing, try to parse full_name
    if not given_name or not surname:
        full_name = data.get('full_name')
        if full_name:
            try:
                given_name, surname = parse_full_name(full_name)
                logger.info(f"Parsed full_name into given_name: {given_name}, surname: {surname}")
            except ValueError as ve:
                logger.warning(f"Failed to parse full_name: {ve}")
                return jsonify({'error': 'Invalid full_name format.'}), 400
        else:
            logger.warning("Missing required fields: given_name and surname.")
            return jsonify({'error': 'Missing required fields.'}), 400

    email = data.get('email')
    phone_number = data.get('phone_number')
    membership_duration_hours = data.get('membership_duration_hours', 24)  # Default to 24 hours

    if not all([given_name, surname, email, phone_number]):
        logger.warning("Missing required fields after processing.")
        return jsonify({'error': 'Missing required fields after processing.'}), 400

    logger.info(f"Processing user: {given_name} {surname}, Email: {email}, Phone: {phone_number}")

    # Process user creation in a separate thread to avoid blocking
    threading.Thread(target=process_user_creation, args=(
        given_name, surname, email, phone_number, membership_duration_hours)).start()

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

    # Mark the token as used
    with app.app_context():
        unlock_token.used = True
        db.session.commit()

    card_number = unlock_token.user.card_number

    # Simulate the card read in a separate thread to avoid blocking
    threading.Thread(target=simulate_unlock, args=(card_number,)).start()

    return jsonify({'message': 'Door is unlocking. Please wait...'}), 200

def simulate_unlock(card_number):
    """
    Simulates the card read to unlock the door.
    """
    try:
        # Authenticate
        access_token, instance_id = get_access_token(
            base_address=BASE_ADDRESS,
            instance_name=INSTANCE_NAME,
            username=KEEP_USERNAME,
            password=KEEP_PASSWORD
        )

        # Retrieve required components
        readers = get_readers(BASE_ADDRESS, access_token, instance_id)
        if not readers:
            logger.error("No Readers found.")
            return
        reader = readers[0]  # Select the first reader

        card_formats = get_card_formats(BASE_ADDRESS, access_token, instance_id)
        if not card_formats:
            logger.error("No Card Formats found.")
            return
        card_format = card_formats[0]  # Select the first card format

        controllers = get_controllers(BASE_ADDRESS, access_token, instance_id)
        if not controllers:
            logger.error("No Controllers found.")
            return
        controller = controllers[0]  # Select the first controller

        # Simulate Card Read
        success = simulate_card_read(
            base_address=BASE_ADDRESS,
            access_token=access_token,
            instance_id=instance_id,
            reader=reader,
            card_format=card_format,
            controller=controller,
            reason=SIMULATION_REASON,
            facility_code=FACILITY_CODE,
            card_number=card_number
        )

        if success:
            logger.info("Unlock simulation successful.")
        else:
            logger.error("Unlock simulation failed.")

    except Exception as e:
        logger.exception(f"Error in simulating unlock: {e}")
@app.route('/test_send_unlock_sms', methods=['GET'])
def test_send_unlock_sms():
    """
    Test route to create a test user and send an unlock link via SMS.
    """
    try:
        # Step 1: Authenticate
        access_token, instance_id = get_access_token(
            base_address=BASE_ADDRESS,
            instance_name=INSTANCE_NAME,
            username=KEEP_USERNAME,
            password=KEEP_PASSWORD
        )

        # Step 2: Get or Create Badge Type
        badge_types = get_badge_types(BASE_ADDRESS, access_token, instance_id)
        badge_type_info = next((bt for bt in badge_types if bt.get("CommonName") == BADGE_TYPE_NAME), None)

        if not badge_type_info:
            logger.info(f"Badge Type '{BADGE_TYPE_NAME}' does not exist. Creating it now.")
            badge_type_response = create_badge_type(BASE_ADDRESS, access_token, instance_id, BADGE_TYPE_NAME)
            if badge_type_response:
                badge_type_info = badge_type_response
            else:
                # If Badge Type already exists (status code 409), retrieve its details
                badge_type_info = get_badge_type_details(BASE_ADDRESS, access_token, instance_id, BADGE_TYPE_NAME)

        # Step 3: Create a Test User
        given_name = "Test"
        surname = "User"
        email = f"test.user{random.randint(1000,9999)}@example.com"
        phone_number = "+18777804236"  # Sending SMS to Twilio number for testing; change as needed
        membership_duration_hours = 24  # 24-hour membership for testing

        # Create the user via CRM API and store in local database
        user = create_user(
            base_address=BASE_ADDRESS,
            access_token=access_token,
            instance_id=instance_id,
            given_name=given_name,
            surname=surname,
            email=email,
            phone_number=phone_number,
            badge_type_info=badge_type_info,
            membership_duration_hours=membership_duration_hours
        )

        # Step 4: Generate Unlock Token and Link
        unlock_token_str = generate_unlock_token(user)
        unlock_link = create_unlock_link(unlock_token_str)

        # Step 5: Send SMS with Unlock Link
        send_sms(phone_number, unlock_link)

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
