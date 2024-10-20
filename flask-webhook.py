from flask import Flask, request, jsonify
import os
import threading
import uuid
import datetime
from datetime import timezone, timedelta
from twilio.rest import Client  # Imported Twilio Client
import requests
import json
import sys
import base64
import random
from bson import BSON  # From pymongo
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# ----------------------------
# Configuration and Constants
# ----------------------------

# Base API URL
BASE_ADDRESS = "https://api.us.acresecurity.cloud"

# Instance Name
INSTANCE_NAME = "ironhorse"  # Replace with your actual instance name

# Administrator Credentials (Set as environment variables)
USERNAME = os.getenv("KEEP_USERNAME", "admin")  # Default to 'admin' if not set
PASSWORD = os.getenv("KEEP_PASSWORD", "P@ssw0rd!")  # Default password

# Badge Type Configuration
BADGE_TYPE_NAME = "Employee Badge"

# Simulation Parameters
SIMULATION_REASON = "Automated Testing of Card Read"
FACILITY_CODE = 100

# Twilio Configuration (Hardcoded Credentials - Not Recommended)
TWILIO_ACCOUNT_SID = 'AC1cfbf4a9ce830facd168f12224731fa3'
TWILIO_AUTH_TOKEN = '173cc74da139e5cfbc0123515e4d72d0'
TWILIO_PHONE_NUMBER = '+18447936399'  # Your Twilio phone number

# Database Configuration (SQLite Example)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///unlock_tokens.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

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
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(20), unique=True, nullable=False)
    card_number = db.Column(db.String(20), unique=True, nullable=False)
    membership_start = db.Column(db.DateTime, nullable=False)
    membership_end = db.Column(db.DateTime, nullable=False)

    def is_membership_active(self):
        now = datetime.datetime.utcnow()
        return self.membership_start <= now <= self.membership_end

class UnlockToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(36), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)

    user = db.relationship('User', backref=db.backref('unlock_tokens', lazy=True))

    def is_valid(self):
        now = datetime.datetime.utcnow()
        return not self.used and now < self.expires_at and self.user.is_membership_active()

# Initialize the database
with app.app_context():
    db.create_all()

# ----------------------------
# Helper Functions (Your Existing Code)
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

        print("Login Successful!\n")
        return access_token, instance_id
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred during login: {http_err}")
        print(f"Response Content: {response.text}")
        sys.exit(1)
    except Exception as err:
        print(f"An error occurred during login: {err}")
        sys.exit(1)

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
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred while retrieving badge types: {http_err}")
        print(f"Response Content: {response.text}")
        sys.exit(1)
    except Exception as err:
        print(f"An error occurred while retrieving badge types: {err}")
        sys.exit(1)

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
        badge_type_id = response_data.get("Key")  # Assuming "Key" is the unique identifier

        if not badge_type_id:
            raise Exception("Badge Type ID not found in the response.")

        print(f"Badge Type '{badge_type_name}' created successfully with ID: {badge_type_id}\n")
        return response_data
    except requests.exceptions.HTTPError as http_err:
        if response.status_code == 409:
            print(f"Badge Type '{badge_type_name}' already exists.\n")
            return None
        else:
            print(f"HTTP error occurred during Badge Type creation: {http_err}")
            print(f"Response Content: {response.text}")
            sys.exit(1)
    except Exception as err:
        print(f"An error occurred during Badge Type creation: {err}")
        sys.exit(1)

def get_badge_type_details(base_address, access_token, instance_id, badge_type_name):
    """
    Retrieves details of a specific Badge Type.

    Returns:
        dict: Details of the Badge Type.

    Raises:
        Exception: If retrieval fails or Badge Type is not found.
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
    # 26-bit range: 0 to 67,108,863
    card_number = random.randint(0, 67108863)
    return card_number

def create_user(base_address, access_token, instance_id, given_name, surname, email, phone_number, badge_type_info):
    """
    Creates a new user in the Keep by Feenics system.

    Returns:
        User: The created User object.
    """
    create_person_endpoint = f"{base_address}/api/f/{instance_id}/people"

    # Generate a 26-bit HID card number
    card_number = generate_card_number()

    # Prepare the payload
    user_data = {
        "GivenName": given_name,
        "Surname": surname,
        "Email": email,
        "PhoneNumber": phone_number,
        "ObjectLinks": [
            {
                "Relation": "BadgeType",
                "CommonName": badge_type_info.get("CommonName"),
                "Href": badge_type_info.get("Href"),
                "LinkedObjectKey": badge_type_info.get("Key")
            }
        ],
        "Metadata": [
            {
                "Application": "CustomApp",
                "Values": json.dumps({"CardNumber": format(card_number, 'x')}),  # Hexadecimal
                "ShouldPublishUpdateEvents": False
            }
        ]
    }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    # Debug: Print the payload
    print("User Data Payload:")
    print(json.dumps(user_data, indent=4))
    print()

    try:
        response = SESSION.post(create_person_endpoint, headers=headers, json=user_data)
        response.raise_for_status()

        response_data = response.json()
        user_id = response_data.get("Key")

        if not user_id:
            raise Exception("User ID not found in the response.")

        print(f"User '{given_name} {surname}' created successfully with ID: {user_id}")
        print(f"Assigned Card Number: {card_number} (Hex: {format(card_number, 'x')})\n")

        # Create User in local database
        membership_start = datetime.datetime.utcnow()
        membership_end = membership_start + timedelta(hours=24)  # Example: 24-hour day pass

        user = User(
            id=int(user_id),
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
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred during user creation: {http_err}")
        print(f"Response Content: {response.text}")
        sys.exit(1)
    except Exception as err:
        print(f"An error occurred during user creation: {err}")
        sys.exit(1)

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
        print(f"Available Readers:\n{json.dumps(readers, indent=4)}\n")
        return readers
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred while retrieving readers: {http_err}")
        print(f"Response Content: {response.text}")
        sys.exit(1)
    except Exception as err:
        print(f"An error occurred while retrieving readers: {err}")
        sys.exit(1)

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
        print(f"Available Card Formats:\n{json.dumps(card_formats, indent=4)}\n")
        return card_formats
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred while retrieving card formats: {http_err}")
        print(f"Response Content: {response.text}")
        sys.exit(1)
    except Exception as err:
        print(f"An error occurred while retrieving card formats: {err}")
        sys.exit(1)

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
        print(f"Available Controllers:\n{json.dumps(controllers, indent=4)}\n")
        return controllers
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred while retrieving controllers: {http_err}")
        print(f"Response Content: {response.text}")
        sys.exit(1)
    except Exception as err:
        print(f"An error occurred while retrieving controllers: {err}")
        sys.exit(1)

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

    # Debug: Print the event data
    print("Event Data:")
    print(json.dumps(event_data, indent=4))
    print()

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

    # Debug: Print the payload
    print("Payload:")
    print(json.dumps(payload, indent=4))
    print()

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    try:
        response = SESSION.post(event_endpoint, headers=headers, json=payload)
        response.raise_for_status()
        print("Card read simulation event published successfully.\n")
        return True
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred during event publishing: {http_err}")
        print(f"Response Content: {response.text}")
        return False
    except Exception as err:
        print(f"An error occurred during event publishing: {err}")
        return False

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
            username=USERNAME,
            password=PASSWORD
        )

        # Step 2: Get or Create Badge Type
        badge_types = get_badge_types(BASE_ADDRESS, access_token, instance_id)
        badge_type_info = next((bt for bt in badge_types if bt.get("CommonName") == BADGE_TYPE_NAME), None)

        if not badge_type_info:
            print(f"Badge Type '{BADGE_TYPE_NAME}' does not exist. Creating it now...\n")
            badge_type_response = create_badge_type(BASE_ADDRESS, access_token, instance_id, BADGE_TYPE_NAME)
            if badge_type_response:
                badge_type_info = badge_type_response
            else:
                # If Badge Type already exists (status code 409), retrieve its details
                badge_type_info = get_badge_type_details(BASE_ADDRESS, access_token, instance_id, BADGE_TYPE_NAME)

        # Step 3: Create User
        # Generate a unique phone number or handle duplicates as needed
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            print(f"User with email {email} already exists.")
            return

        # Create the user via CRM API
        user = create_user(
            base_address=BASE_ADDRESS,
            access_token=access_token,
            instance_id=instance_id,
            given_name=given_name,
            surname=surname,
            email=email,
            phone_number=phone_number,
            badge_type_info=badge_type_info
        )

        # Step 4: Generate Unlock Link
        unlock_token_str = generate_unlock_token(user)
        unlock_link = create_unlock_link(unlock_token_str)

        # Step 5: Send SMS with Unlock Link
        send_sms(phone_number, unlock_link)

    except Exception as e:
        print(f"Error in processing user creation: {e}")

def generate_unlock_token(user):
    """
    Generates a unique unlock token for a user, valid until the membership ends.
    """
    token = str(uuid.uuid4())
    expires_at = user.membership_end  # Token expires when membership ends

    unlock_token = UnlockToken(
        token=token,
        user_id=user.id,
        expires_at=expires_at
    )

    db.session.add(unlock_token)
    db.session.commit()

    return token

def create_unlock_link(token):
    """
    Creates a secure unlock link containing the token.
    """
    base_url = "https://yourdomain.com/unlock"  # Replace with your actual domain
    return f"{base_url}?token={token}"

def send_sms(to_phone_number, unlock_link):
    """
    Sends an SMS with the unlock link to the user's phone number.
    """
    if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER]):
        print("Twilio credentials are not set properly.")
        return

    message_body = f"Welcome! Click the link to unlock your door: {unlock_link}\nNote: This link is valid for the duration of your membership."

    try:
        message = client.messages.create(
            body=message_body,
            from_=TWILIO_PHONE_NUMBER,
            to=to_phone_number
        )
        print(f"SMS sent to {to_phone_number}: SID {message.sid}")
    except Exception as e:
        print(f"Failed to send SMS: {e}")

# ----------------------------
# Unlock Token Management
# ----------------------------

def validate_unlock_token(token):
    """
    Validates the unlock token.
    """
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
# Unlock Endpoint
# ----------------------------

@app.route('/unlock', methods=['GET'])
def handle_unlock():
    token = request.args.get('token')

    if not token:
        return jsonify({'error': 'Token is missing'}), 400

    is_valid, result = validate_unlock_token(token)

    if not is_valid:
        return jsonify({'error': result}), 400

    unlock_token = result

    # Mark the token as used
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
            username=USERNAME,
            password=PASSWORD
        )

        # Retrieve required components
        readers = get_readers(BASE_ADDRESS, access_token, instance_id)
        if not readers:
            print("No Readers found.")
            return
        reader = readers[0]  # Select the first reader

        card_formats = get_card_formats(BASE_ADDRESS, access_token, instance_id)
        if not card_formats:
            print("No Card Formats found.")
            return
        card_format = card_formats[0]  # Select the first card format

        controllers = get_controllers(BASE_ADDRESS, access_token, instance_id)
        if not controllers:
            print("No Controllers found.")
            return
        controller = controllers[0]  # Select the first controller

        # Simulate Card Read
        simulate_card_read(
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

    except Exception as e:
        print(f"Error in simulating unlock: {e}")

# ----------------------------
# Webhook Endpoint
# ----------------------------

@app.route('/webhook', methods=['POST'])
def handle_webhook():
    data = request.json

    # Validate incoming data
    required_fields = ['given_name', 'surname', 'email', 'phone_number']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Missing required fields'}), 400

    given_name = data['given_name']
    surname = data['surname']
    email = data['email']
    phone_number = data['phone_number']
    membership_duration_hours = data.get('membership_duration_hours', 24)  # Default to 24 hours

    # Process user creation in a separate thread to avoid blocking
    threading.Thread(target=process_user_creation, args=(given_name, surname, email, phone_number, membership_duration_hours)).start()

    return jsonify({'status': 'User creation in progress'}), 200

# ----------------------------
# Main Execution
# ----------------------------

if __name__ == "__main__":
    # Run the Flask app
    app.run(host='0.0.0.0', port=5000, debug=True)
