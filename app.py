import os
import sys
import json
import uuid
import random
import base64
import logging
import threading
import datetime
from datetime import timezone, timedelta

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
BADGE_TYPE_NAME = os.getenv("BADGE_TYPE_NAME", "Employee Badge")
SIMULATION_REASON = os.getenv("SIMULATION_REASON", "Automated Testing of Card Read")
FACILITY_CODE = int(os.getenv("FACILITY_CODE", 111))  # Set your facility code here
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
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=False, nullable=False)
    phone_number = db.Column(db.String(20), unique=False, nullable=False)
    card_number = db.Column(db.Integer, unique=False, nullable=False)
    facility_code = db.Column(db.Integer, unique=False, nullable=False)
    issue_code = db.Column(db.Integer, unique=False, nullable=True)
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

def get_instance_settings(base_address, access_token, instance_id):
    """
    Retrieves the instance settings, including IssueCodeSize.
    """
    settings_endpoint = f"{base_address}/api/f/{instance_id}/settings"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.get(settings_endpoint, headers=headers)
        response.raise_for_status()
        settings = response.json()
        logger.info("Retrieved instance settings successfully.")
        return settings
    except Exception as err:
        logger.error(f"Error retrieving instance settings: {err}")
        raise

def get_issue_code_size(settings):
    """
    Extracts the IssueCodeSize from the instance settings.
    """
    issue_code_size = settings.get('IssueCodeSize', 0)
    logger.info(f"IssueCodeSize from instance settings: {issue_code_size}")
    return issue_code_size

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

        badge_types_data = response.json()

        if isinstance(badge_types_data, dict) and 'value' in badge_types_data:
            badge_types = badge_types_data['value']
        elif isinstance(badge_types_data, list):
            badge_types = badge_types_data
        else:
            badge_types = []
            logger.warning("Unexpected format for badge_types_data.")

        logger.info(f"Retrieved {len(badge_types)} badge types.")
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
    """
    badge_types = get_badge_types(base_address, access_token, instance_id)

    for bt in badge_types:
        if bt.get("CommonName") == badge_type_name:
            return bt

    raise Exception(f"Badge Type '{badge_type_name}' not found after creation.")

def generate_card_number():
    """
    Generates a random card number within the valid range.

    Returns:
        int: A card number in the range of 1 to 65535.
    """
    card_number = random.randint(1, 65535)
    return card_number

def get_access_levels(base_address, access_token, instance_id):
    access_levels_endpoint = f"{base_address}/api/f/{instance_id}/accesslevels"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.get(access_levels_endpoint, headers=headers)
        response.raise_for_status()
        access_levels_data = response.json()

        # Handle both list and dict responses
        if isinstance(access_levels_data, dict):
            access_levels = access_levels_data.get('value', [])
            if not access_levels:
                logger.warning("No access levels found under 'value' key.")
        elif isinstance(access_levels_data, list):
            access_levels = access_levels_data
        else:
            logger.error("Unexpected data format for access levels.")
            access_levels = []

        logger.info(f"Retrieved {len(access_levels)} access levels.")
        return access_levels
    except Exception as err:
        logger.error(f"Error retrieving access levels: {err}")
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
        card_formats_data = response.json()

        # Handle both dict and list responses
        if isinstance(card_formats_data, dict):
            card_formats = card_formats_data.get('value', [])
            if not card_formats:
                logger.warning("No card formats found under 'value' key.")
        elif isinstance(card_formats_data, list):
            card_formats = card_formats_data
        else:
            logger.error("Unexpected data format for card formats.")
            card_formats = []

        # Log the retrieved card formats for debugging
        logger.debug(f"Card Formats Data: {card_formats_data}")
        logger.info(f"Retrieved {len(card_formats)} card formats.")
        return card_formats
    except Exception as err:
        logger.error(f"Error retrieving card formats: {err}")
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
        readers_data = response.json()

        # Handle both dict and list responses
        if isinstance(readers_data, dict):
            readers = readers_data.get('value', [])
            if not readers:
                logger.warning("No readers found under 'value' key.")
        elif isinstance(readers_data, list):
            readers = readers_data
        else:
            logger.error("Unexpected data format for readers.")
            readers = []

        logger.info(f"Retrieved {len(readers)} readers.")
        return readers
    except Exception as err:
        logger.error(f"Error retrieving readers: {err}")
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
        controllers_data = response.json()

        # Handle both dict and list responses
        if isinstance(controllers_data, dict):
            controllers = controllers_data.get('value', [])
            if not controllers:
                logger.warning("No controllers found under 'value' key.")
        elif isinstance(controllers_data, list):
            controllers = controllers_data
        else:
            logger.error("Unexpected data format for controllers.")
            controllers = []

        logger.info(f"Retrieved {len(controllers)} controllers.")
        return controllers
    except Exception as err:
        logger.error(f"Error retrieving controllers: {err}")
        raise

def create_user(base_address, access_token, instance_id, first_name, last_name, email, phone_number, badge_type_info, membership_duration_hours):
    """
    Creates a new user in the Keep by Feenics system with the 'Access' access level.

    Returns:
        str: The unlock link generated for the user.
    """
    create_person_endpoint = f"{base_address}/api/f/{instance_id}/people"

    card_number = generate_card_number()
    facility_code = FACILITY_CODE  # Use the global facility code

    # Generate issue code (set to a fixed value or randomly)
    issue_code = random.randint(1, 9999)  # Example: 4-digit issue code

    # Prepare the current and expiration times
    active_on = datetime.datetime.utcnow().isoformat() + "Z"
    expires_on = (datetime.datetime.utcnow() + timedelta(hours=membership_duration_hours)).isoformat() + "Z"

    # Retrieve the access level named 'Access'
    access_levels = get_access_levels(base_address, access_token, instance_id)
    if not access_levels:
        logger.error("No access levels found.")
        raise Exception("No access levels available to assign to the user.")

    # Find the access level with CommonName 'Access'
    access_level = next((al for al in access_levels if al.get('CommonName') == 'Access'), None)
    if not access_level:
        logger.error("Access level 'Access' not found.")
        raise Exception("Access level 'Access' is required for user assignment.")

    # Prepare Access Level Assignment
    access_level_assignments = [
        {
            "$type": "Feenics.Keep.WebApi.Model.AccessLevelAssignmentInfo, Feenics.Keep.WebApi.Model",
            "AccessLevelKey": access_level.get("Key"),
            "ActiveOn": active_on,
            "ExpiresOn": expires_on
        }
    ]

    # Retrieve card formats
    card_formats = get_card_formats(base_address, access_token, instance_id)
    if not card_formats:
        logger.error("No card formats found.")
        raise Exception("No card formats available for assignment.")

    # Select the card format with CommonName '111'
    selected_card_format = next((cf for cf in card_formats if cf.get('CommonName') == '111'), None)
    if not selected_card_format:
        logger.error("Card format '111' not found.")
        raise Exception("Card format '111' is required for card assignment.")

    logger.info(f"Selected Card Format: {selected_card_format}")

    user_data = {
        "$type": "Feenics.Keep.WebApi.Model.PersonInfo, Feenics.Keep.WebApi.Model",
        "CommonName": f"{first_name} {last_name}",
        "GivenName": first_name,
        "Surname": last_name,
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
                "FacilityCode": int(facility_code),
                "IssueCode": int(issue_code),  # Use generated IssueCode
                "CardFormatKey": selected_card_format.get("Key"),
                "ActiveOn": active_on,
                "ExpiresOn": expires_on,
                "AntiPassbackExempt": False,
                "ExtendedAccess": False
            }
        ],
        "AccessLevelAssignments": access_level_assignments,
        "Metadata": [
            {
                "$type": "Feenics.Keep.WebApi.Model.MetadataItem, Feenics.Keep.WebApi.Model",
                "Application": "CustomApp",
                "Values": json.dumps({
                    "CardNumber": str(card_number),
                    "FacilityCode": str(facility_code),
                    "IssueCode": str(issue_code)
                }),
                "ShouldPublishUpdateEvents": False
            }
        ]
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        # Log the user data payload for debugging
        logger.debug(f"User Data Payload: {json.dumps(user_data, indent=2)}")

        response = SESSION.post(create_person_endpoint, headers=headers, json=user_data)
        response.raise_for_status()

        response_data = response.json()
        user_id = response_data.get("Key")

        if not user_id:
            raise Exception("User ID not found in the response.")

        logger.info(f"User '{first_name} {last_name}' created successfully with ID: {user_id}")
        logger.info(f"Assigned Card Number: {card_number}, Facility Code: {facility_code}, Issue Code: {issue_code}")

        # Create User in local database
        membership_start = datetime.datetime.utcnow()
        membership_end = membership_start + timedelta(hours=membership_duration_hours)

        user = User(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone_number=phone_number,
            card_number=card_number,
            facility_code=facility_code,
            issue_code=issue_code,
            membership_start=membership_start,
            membership_end=membership_end
        )

        db.session.add(user)
        db.session.commit()

        # Generate Unlock Token and Link
        unlock_token_str = generate_unlock_token(user.id)
        unlock_link = create_unlock_link(unlock_token_str)

        # Send SMS with Unlock Link
        sms_sent = send_sms(phone_number, unlock_link)
        if not sms_sent:
            logger.warning(f"SMS sending failed for user '{first_name} {last_name}'.")

        return unlock_link  # Return the unlock link to be included in the response

    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 400:
            logger.error(f"Bad Request during user creation: {response.text}")
        else:
            logger.error(f"HTTP error during user creation: {http_err}")
            logger.error(f"Response Content: {response.text}")
        raise
    except Exception as err:
        logger.error(f"Error during user creation: {err}")
        raise

def simulate_card_read(base_address, access_token, instance_id, reader, card_format, controller, reason, facility_code, card_number, issue_code):
    """
    Simulates a card read by publishing a simulateCardRead event.

    Returns:
        bool: True if successful, False otherwise.
    """
    event_endpoint = f"{base_address}/api/f/{instance_id}/eventmessagesink"

    # Ensure card_number and facility_code are integers
    try:
        card_number_int = int(card_number)
        facility_code_int = int(facility_code)
        issue_code_int = int(issue_code) if issue_code else None
    except ValueError as e:
        logger.error(f"Invalid card number, facility code, or issue code: {e}")
        return False

    # Construct EventData
    event_data = {
        "Reason": reason,
        "FacilityCode": facility_code_int,
        "EncodedCardNumber": card_number_int,
    }

    # Include IssueCode if available
    if issue_code_int is not None:
        event_data["IssueCode"] = issue_code_int

    logger.info(f"Event Data before encoding: {event_data}")

    # Convert EventData to BSON and then to Base64
    event_data_bson = BSON.encode(event_data)
    event_data_base64 = base64.b64encode(event_data_bson).decode('utf-8')

    logger.info(f"EventDataBsonBase64: {event_data_base64}")

    # Construct the payload
    payload = {
        "$type": "Feenics.Keep.WebApi.Model.EventMessagePosting, Feenics.Keep.WebApi.Model",
        "OccurredOn": datetime.datetime.now(timezone.utc).isoformat() + "Z",
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
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error during event publishing: {http_err}")
        logger.error(f"Response Status Code: {response.status_code}")
        logger.error(f"Response Content: {response.text}")
        return False
    except Exception as err:
        logger.error(f"Error during event publishing: {err}")
        return False

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

# ----------------------------
# User Creation and Messaging Workflow
# ----------------------------

def process_user_creation(first_name, last_name, email, phone_number, membership_duration_hours=24):
    """
    Complete workflow to create a user in CRM, store membership info, generate unlock link, and send an SMS.
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

            # Step 2: Retrieve Instance Settings
            instance_settings = get_instance_settings(BASE_ADDRESS, access_token, instance_id)
            issue_code_size = get_issue_code_size(instance_settings)

            # Step 3: Get or Create Badge Type
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

            # Step 4: Check if user exists in the database
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                logger.info(f"User with email {email} already exists.")
                return

            # Create the user via CRM API and store in local database
            user = create_user(
                base_address=BASE_ADDRESS,
                access_token=access_token,
                instance_id=instance_id,
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone_number=phone_number,
                badge_type_info=badge_type_info,
                membership_duration_hours=membership_duration_hours,
                issue_code_size=issue_code_size
            )

            # Step 5: Generate Unlock Token and Link
            unlock_token_str = generate_unlock_token(user.id)
            unlock_link = create_unlock_link(unlock_token_str)

            # Step 6: Send SMS with Unlock Link
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

    card_number = unlock_token.user.card_number
    facility_code = unlock_token.user.facility_code
    issue_code = unlock_token.user.issue_code

    logger.info(f"Simulating unlock for card number: {card_number}, facility code: {facility_code}, issue_code: {issue_code}")

    # Simulate the card read in a separate thread to avoid blocking
    threading.Thread(target=simulate_unlock, args=(card_number, facility_code, issue_code)).start()

    return jsonify({'message': 'Door is unlocking. Please wait...'}), 200

def simulate_unlock(card_number, facility_code, issue_code):
    """
    Simulates the card read to unlock the door.
    """
    try:
        with app.app_context():
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

            # Replace 'YOUR_READER_NAME' with your actual reader name
            reader = next((r for r in readers if r.get('CommonName') == 'YOUR_READER_NAME'), None)
            if not reader:
                logger.error("Specified Reader not found.")
                return

            card_formats = get_card_formats(BASE_ADDRESS, access_token, instance_id)
            if not card_formats:
                logger.error("No Card Formats found.")
                return

            # Select the card format with CommonName '111'
            card_format = next((cf for cf in card_formats if cf.get('CommonName') == '111'), None)
            if not card_format:
                logger.error("Card format '111' not found.")
                return

            controllers = get_controllers(BASE_ADDRESS, access_token, instance_id)
            if not controllers:
                logger.error("No Controllers found.")
                return

            # Replace 'YOUR_CONTROLLER_NAME' with your actual controller name
            controller = next((c for c in controllers if c.get('CommonName') == 'YOUR_CONTROLLER_NAME'), None)
            if not controller:
                logger.error("Specified Controller not found.")
                return

            # Simulate Card Read
            success = simulate_card_read(
                base_address=BASE_ADDRESS,
                access_token=access_token,
                instance_id=instance_id,
                reader=reader,
                card_format=card_format,
                controller=controller,
                reason=SIMULATION_REASON,
                facility_code=facility_code,
                card_number=card_number,
                issue_code=issue_code
            )

            if success:
                logger.info("Unlock simulation successful.")
            else:
                logger.error("Unlock simulation failed.")

    except Exception as e:
        logger.exception(f"Error in simulating unlock: {e}")

# ----------------------------
# Main Execution
# ----------------------------

if __name__ == "__main__":
    # Get the port from environment variables (for deployment platforms like Render)
    port = int(os.getenv("PORT", 5000))  # Default to 5000 if PORT is not set
    app.run(host='0.0.0.0', port=port)
