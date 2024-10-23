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
import time

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

def create_user(base_address, access_token, instance_id, first_name, last_name, email, phone_number, badge_type_info, membership_duration_hours, issue_code_size):
    """
    Creates a new user in the Keep by Feenics system.

    Returns:
        tuple: (User object, user_id)
    """
    create_person_endpoint = f"{base_address}/api/f/{instance_id}/people"

    # Proceed to create user
    card_number = generate_card_number()
    facility_code = FACILITY_CODE

    # Generate IssueCode if required
    if issue_code_size > 0:
        max_issue_code = (1 << (issue_code_size * 8)) - 1  # Calculate max value based on size in bytes
        issue_code = random.randint(1, max_issue_code)
    else:
        issue_code = None  # IssueCode not required

    # Prepare the current and expiration times
    active_on = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    expires_on = (datetime.datetime.utcnow() + timedelta(hours=membership_duration_hours)).replace(microsecond=0).isoformat() + "Z"

    # Retrieve card formats
    card_formats = get_card_formats(base_address, access_token, instance_id)
    if not card_formats:
        logger.error("No card formats found.")
        raise Exception("No card formats available to assign to the card.")

    # Use the first available card format
    selected_card_format = card_formats[0]
    logger.info(f"Using card format: {selected_card_format.get('CommonName')}")

    # Prepare Card Assignment
    card_assignment = {
        "$type": "Feenics.Keep.WebApi.Model.CardAssignmentInfo, Feenics.Keep.WebApi.Model",
        "EncodedCardNumber": int(card_number),
        "DisplayCardNumber": str(card_number),
        "FacilityCode": int(facility_code),
        "ActiveOn": active_on,
        "ExpiresOn": expires_on,
        "CardFormat": {
            "LinkedObjectKey": selected_card_format['Key'],
        },
        "AntiPassbackExempt": False,
        "ExtendedAccess": False,
        "PinExempt": True,
        "IsDisabled": False,
        "ManagerLevel": 0,
        "Note": None,
        "OriginalUseCount": None,
        "CurrentUseCount": 0,
    }

    # Include IssueCode if required
    if issue_code is not None:
        card_assignment["IssueCode"] = int(issue_code)

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
        "CardAssignments": [card_assignment],
        # Remove AccessLevelAssignments from here
        # "AccessLevelAssignments": access_level_assignments,  # Remove this line
        "Metadata": [
            {
                "$type": "Feenics.Keep.WebApi.Model.MetadataItem, Feenics.Keep.WebApi.Model",
                "Application": "CustomApp",
                "Values": json.dumps({
                    "CardNumber": str(card_number),
                    "FacilityCode": str(facility_code),
                    "IssueCode": str(issue_code) if issue_code else None,
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
        response = SESSION.post(create_person_endpoint, headers=headers, json=user_data)
        response.raise_for_status()

        response_data = response.json()
        user_id = response_data.get("Key")

        if not user_id:
            raise Exception("User ID not found in the response.")

        logger.info(f"User '{first_name} {last_name}' created successfully with ID: {user_id}")
        logger.info(f"Assigned Card Number: {card_number}, Facility Code: {facility_code}, IssueCode: {issue_code}")

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
            issue_code=issue_code if issue_code else 0,
            membership_start=membership_start,
            membership_end=membership_end
        )

        db.session.add(user)
        db.session.commit()

        return user, user_id  # Return both user and user_id
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error during user creation: {http_err}")
        logger.error(f"Response Content: {response.text}")
        raise
    except Exception as err:
        logger.error(f"Error during user creation: {err}")
        raise
def assign_access_levels_to_user(base_address, access_token, instance_id, person_key, access_levels):
    """
    Assigns access levels to a person without setting active and expiration dates.

    Args:
        base_address (str): Base URL of the API.
        access_token (str): Bearer token for authentication.
        instance_id (str): Instance ID from the API.
        person_key (str): The unique key of the person (user).
        access_levels (list): List of access level objects, each containing an 'Href'.
    """
    assign_endpoint = f"{base_address}/api/f/{instance_id}/people/{person_key}/accesslevels"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    # Prepare the list of access level Hrefs
    access_level_hrefs = [al['Href'] for al in access_levels if al.get('Href')]

    if not access_level_hrefs:
        logger.error("No valid access level Hrefs found.")
        raise ValueError("Access levels must include 'Href' fields.")

    # If assigning multiple access levels, send as a list; otherwise, send as a single string
    payload = access_level_hrefs if len(access_level_hrefs) > 1 else access_level_hrefs[0]

    # Logging for debugging
    logger.debug(f"Assign Endpoint: {assign_endpoint}")
    logger.debug(f"Access Level Hrefs Payload: {json.dumps(payload, indent=2)}")

    try:
        response = SESSION.put(assign_endpoint, headers=headers, json=payload)
        response.raise_for_status()
        logger.info(f"Access levels assigned to user {person_key} successfully.")
    except requests.exceptions.HTTPError as http_err:
        logger.error(f"HTTP error during access level assignment: {http_err}")
        logger.error(f"Response Content: {response.text}")
        raise
    except Exception as err:
        logger.error(f"Error assigning access levels to user {person_key}: {err}")
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

        # Handle both list and dict responses
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

        # Handle both list and dict responses
        if isinstance(card_formats_data, dict):
            card_formats = card_formats_data.get('value', [])
            if not card_formats:
                logger.warning("No card formats found under 'value' key.")
        elif isinstance(card_formats_data, list):
            card_formats = card_formats_data
        else:
            logger.error("Unexpected data format for card formats.")
            card_formats = []

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
        controllers_data = response.json()

        # Handle both list and dict responses
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

            # Step 4: Check if user exists in the local database
            existing_user = User.query.filter_by(email=email).first()
            if existing_user:
                logger.info(f"User with email {email} already exists in the local database.")
                return

            # Step 5: Retrieve all access levels
            access_levels = get_access_levels(BASE_ADDRESS, access_token, instance_id)
            if not access_levels:
                logger.error("No access levels found.")
                raise Exception("No access levels available to assign to the user.")

            # Prepare active_on and expires_on
            active_on = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
            expires_on = (datetime.datetime.utcnow() + timedelta(hours=membership_duration_hours)).replace(microsecond=0).isoformat() + "Z"

            # Step 6: Create the user via CRM API and store in local database
            user, user_id = create_user(
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

            # Step 7: Assign Access Levels to the User
            assign_access_levels_to_user_with_dates(
                base_address=BASE_ADDRESS,
                access_token=access_token,
                instance_id=instance_id,
                person_key=user_id,
                access_levels=access_levels,
                active_on=active_on,
                expires_on=expires_on
            )

            # Optional: Wait for access levels to be processed
            time.sleep(2)

            # Step 8: Generate Unlock Token and Link
            unlock_token_str = generate_unlock_token(user.id)
            unlock_link = create_unlock_link(unlock_token_str)

            # Step 9: Send SMS with Unlock Link
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

    logger.info(f"Simulating unlock for card number: {card_number}, facility code: {facility_code}, issue code: {issue_code}")

    # Simulate the card read in a separate thread to avoid blocking
    threading.Thread(target=simulate_unlock, args=(card_number, facility_code, issue_code)).start()

    return jsonify({'message': 'Door is unlocking. Please wait...'}), 200

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
        "OccurredOn": datetime.datetime.utcnow().replace(microsecond=0).isoformat() + 'Z',
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

            # Log available readers
            logger.info("Available Readers:")
            for reader_item in readers:
                logger.info(f"Reader Name: {reader_item.get('CommonName')}, Key: {reader_item.get('Key')}")

            # Specify the reader's name
            reader_name = 'Front door'  # Replace with your reader's name from logs
            reader = next((r for r in readers if r.get('CommonName') == reader_name), None)
            if not reader:
                logger.warning(f"Specified Reader '{reader_name}' not found. Using the first available reader.")
                reader = readers[0]
            logger.info(f"Using reader: {reader.get('CommonName')}")

            card_formats = get_card_formats(BASE_ADDRESS, access_token, instance_id)
            if not card_formats:
                logger.error("No Card Formats found.")
                return

            # Use the first available card format
            card_format = card_formats[0]
            logger.info(f"Using card format: {card_format.get('CommonName')}")

            controllers = get_controllers(BASE_ADDRESS, access_token, instance_id)
            if not controllers:
                logger.error("No Controllers found.")
                return

            # Log available controllers
            logger.info("Available Controllers:")
            for controller_item in controllers:
                logger.info(f"Controller Name: {controller_item.get('CommonName')}, Key: {controller_item.get('Key')}")

            # Specify the controller's name
            controller_name = 'Controller'  # Replace with your controller's name from logs
            controller = next((c for c in controllers if c.get('CommonName') == controller_name), None)
            if not controller:
                logger.warning(f"Specified Controller '{controller_name}' not found. Using the first available controller.")
                controller = controllers[0]
            logger.info(f"Using controller: {controller.get('CommonName')}")

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
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000)
