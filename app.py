import datetime
import json
import logging
import random
import threading
import base64

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import requests
from bson import BSON

# Configure Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Flask Application Setup
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///access_control.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize Database and Migration
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Constants and Configuration
BASE_ADDRESS = "https://your-keep-instance.com"  # Replace with your Keep instance address
INSTANCE_NAME = "YourInstanceName"               # Replace with your instance name
KEEP_USERNAME = "your_username"                  # Replace with your Keep username
KEEP_PASSWORD = "your_password"                  # Replace with your Keep password
FACILITY_CODE = 1  # Example facility code (must be between 1 and 255)
SIMULATION_REASON = "Test Unlock"

# Initialize Session
SESSION = requests.Session()

# Database Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=False, nullable=False)
    phone_number = db.Column(db.String(20), unique=False, nullable=False)
    facility_code = db.Column(db.Integer, nullable=False)
    card_number = db.Column(db.Integer, unique=True, nullable=False)                  # 16-bit Card Number
    display_card_number = db.Column(db.String(5), unique=True, nullable=False)          # 5-digit Display Card Number
    membership_start = db.Column(db.DateTime, nullable=False)
    membership_end = db.Column(db.DateTime, nullable=False)

    def is_membership_active(self):
        now = datetime.datetime.utcnow()
        return self.membership_start <= now <= self.membership_end

class UnlockToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(100), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    user = db.relationship('User', backref=db.backref('unlock_tokens', lazy=True))

# Utility Functions
def generate_card_number():
    """Generates a unique 16-bit card number."""
    while True:
        card_number = random.randint(1, 65535)
        if not User.query.filter_by(card_number=card_number).first():
            return card_number

def get_access_token(base_address, instance_name, username, password):
    """
    Authenticates with the Keep API and retrieves an access token.
    """
    auth_endpoint = f"{base_address}/api/f/{instance_name}/auth/token"
    payload = {
        "Username": username,
        "Password": password
    }
    headers = {
        "Content-Type": "application/json"
    }
    response = SESSION.post(auth_endpoint, headers=headers, json=payload)
    response.raise_for_status()
    data = response.json()
    access_token = data.get("access_token")
    instance_id = data.get("instance_id")
    return access_token, instance_id

def get_readers(base_address, access_token, instance_id):
    """
    Retrieves the list of readers from the Keep API.
    """
    readers_endpoint = f"{base_address}/api/f/{instance_id}/readers"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = SESSION.get(readers_endpoint, headers=headers)
    response.raise_for_status()
    return response.json()

def get_card_formats(base_address, access_token, instance_id):
    """
    Retrieves the list of card formats from the Keep API.
    """
    card_formats_endpoint = f"{base_address}/api/f/{instance_id}/cardformats"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = SESSION.get(card_formats_endpoint, headers=headers)
    response.raise_for_status()
    return response.json()

def get_controllers(base_address, access_token, instance_id):
    """
    Retrieves the list of controllers from the Keep API.
    """
    controllers_endpoint = f"{base_address}/api/f/{instance_id}/controllers"
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = SESSION.get(controllers_endpoint, headers=headers)
    response.raise_for_status()
    return response.json()

# Formatting Function
def format_hid_16bit(facility_code, card_number):
    """
    Formats card credentials into a simplified 16-bit format by excluding parity bits.
    """
    # Validate card number range (16 bits)
    if not 0 < card_number <= 65535:
        return None, "Card number must be between 1 and 65535"
    
    # Directly use the raw card number as the formatted number
    formatted_number = str(card_number)
    
    logger.debug(f"Formatted Number (16-bit): {formatted_number}")
    
    return formatted_number, None

# User Creation Function
def create_user(base_address, access_token, instance_id, first_name, last_name, email, phone_number, badge_type_info, membership_duration_hours):
    """
    Creates a new user in the Keep by Feenics system and stores membership information locally.
    """
    try:
        with app.app_context():
            # Step 1: Generate and Format Card Number
            card_number = generate_card_number()  # Raw 16-bit number
            facility_code = FACILITY_CODE  # From environment variable
            logger.debug(f"Generated Card Number: {card_number}, Facility Code: {facility_code}")

            # Format the card number into a 16-bit number (without parity bits)
            formatted_card_number, error_message = format_hid_16bit(facility_code, card_number)
            if formatted_card_number is None:
                logger.error(f"Error formatting card number: {error_message}")
                raise ValueError(error_message)
            logger.debug(f"Formatted Card Number (16-bit): {formatted_card_number}")

            # Format the display card number as a 5-digit string with leading zeros
            display_card_number = f"{card_number:05}"

            # Prepare other data (active_on, expires_on, etc.)
            active_on = datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
            expires_on = (datetime.datetime.utcnow() + datetime.timedelta(hours=membership_duration_hours)).replace(microsecond=0).isoformat() + "Z"

            # Retrieve card formats and other necessary data
            card_formats = get_card_formats(base_address, access_token, instance_id)
            if not card_formats:
                logger.error("No card formats found.")
                raise Exception("No card formats available to assign to the card.")
            selected_card_format = card_formats[0]
            logger.info(f"Using card format: {selected_card_format.get('CommonName')}")

            # Prepare card assignment data
            card_assignment = {
                "$type": "Feenics.Keep.WebApi.Model.CardAssignmentInfo, Feenics.Keep.WebApi.Model",
                "EncodedCardNumber": int(formatted_card_number),  # Now 16-bit
                "DisplayCardNumber": display_card_number,        # 5-digit
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

            # Prepare user data for CRM API
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
                "Metadata": [
                    {
                        "$type": "Feenics.Keep.WebApi.Model.MetadataItem, Feenics.Keep.WebApi.Model",
                        "Application": "CustomApp",
                        "Values": json.dumps({
                            "CardNumber": str(card_number),           # Raw 16-bit Card Number
                            "FacilityCode": str(facility_code)        # Facility Code
                        }),
                        "ShouldPublishUpdateEvents": False
                    }
                ]
            }

            # Define headers for CRM API request
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }

            # Make CRM API request to create user
            create_person_endpoint = f"{base_address}/api/f/{instance_id}/people"
            response = SESSION.post(create_person_endpoint, headers=headers, json=user_data)
            response.raise_for_status()

            response_data = response.json()
            user_id = response_data.get("Key")
            if not user_id:
                raise Exception("User ID not found in the response.")

            logger.info(f"User '{first_name} {last_name}' created successfully with ID: {user_id}")
            logger.info(f"Assigned Card Number: {card_number}, Facility Code: {facility_code}")

            # Create user in local database
            membership_start = datetime.datetime.utcnow()
            membership_end = membership_start + datetime.timedelta(hours=membership_duration_hours)

            user = User(
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone_number=phone_number,
                card_number=card_number,                      # 16-bit Card Number
                display_card_number=display_card_number,      # 5-digit Display Card Number
                facility_code=facility_code,
                membership_start=membership_start,
                membership_end=membership_end
            )

            db.session.add(user)
            db.session.commit()

            return user, user_id  # Return both user and user_id

    # Unlock Simulation Function
    def simulate_unlock(formatted_card_number, facility_code):
        """
        Simulates the card read to unlock the door using the 16-bit formatted_card_number.
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

                # Simulate Card Read using the 16-bit formatted number
                success = simulate_card_read(
                    base_address=BASE_ADDRESS,
                    access_token=access_token,
                    instance_id=instance_id,
                    reader=reader,
                    card_format=card_format,
                    controller=controller,
                    reason=SIMULATION_REASON,
                    facility_code=facility_code,
                    formatted_card_number=formatted_card_number  # Now 16-bit
                )

                if success:
                    logger.info("Unlock simulation successful.")
                else:
                    logger.error("Unlock simulation failed.")

        except Exception as e:
            logger.exception(f"Error in simulating unlock: {e}")

    # Card Read Simulation Function
    def simulate_card_read(base_address, access_token, instance_id, reader, card_format, controller, reason, facility_code, formatted_card_number):
        """
        Simulates a card read by publishing a simulateCardRead event using the 16-bit formatted_card_number.
        
        Returns:
            bool: True if successful, False otherwise.
        """
        event_endpoint = f"{base_address}/api/f/{instance_id}/eventmessagesink"

        # Ensure formatted_card_number and facility_code are integers
        try:
            card_number_int = int(formatted_card_number)  # Now 16-bit
            facility_code_int = int(facility_code)
        except ValueError as e:
            logger.error(f"Invalid formatted card number or facility code: {e}")
            return False

        # Construct EventData
        event_data = {
            "Reason": reason,
            "FacilityCode": facility_code_int,
            "EncodedCardNumber": card_number_int,  # Now 16-bit
        }

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

    # Unlock Token Validation Function
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

            # Ensure that the card number used is 16-bit
            if not 0 < unlock_token.user.card_number <= 65535:
                return False, "Invalid card number."

            return True, unlock_token

    # Flask Route for Unlocking
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

        # Retrieve the 16-bit card number
        card_number = unlock_token.user.card_number
        facility_code = unlock_token.user.facility_code
        formatted_card_number = unlock_token.user.card_number  # Now using 16-bit card_number

        logger.info(f"Simulating unlock for card number: {formatted_card_number}, facility code: {facility_code}")

        # Simulate the card read in a separate thread to avoid blocking
        threading.Thread(target=simulate_unlock, args=(formatted_card_number, facility_code)).start()

        return jsonify({'message': 'Door is unlocking. Please wait...'}), 200

    # Additional Routes and Functions (If Any)
    # Example: Route to create a new user (for testing purposes)
    @app.route('/create_user', methods=['POST'])
    def api_create_user():
        data = request.get_json()
        required_fields = ['first_name', 'last_name', 'email', 'phone_number', 'badge_type_info', 'membership_duration_hours']
        if not all(field in data for field in required_fields):
            return jsonify({'error': 'Missing required fields.'}), 400

        try:
            user, user_id = create_user(
                base_address=BASE_ADDRESS,
                access_token=get_access_token(BASE_ADDRESS, INSTANCE_NAME, KEEP_USERNAME, KEEP_PASSWORD)[0],
                instance_id=get_access_token(BASE_ADDRESS, INSTANCE_NAME, KEEP_USERNAME, KEEP_PASSWORD)[1],
                first_name=data['first_name'],
                last_name=data['last_name'],
                email=data['email'],
                phone_number=data['phone_number'],
                badge_type_info=data['badge_type_info'],
                membership_duration_hours=data['membership_duration_hours']
            )
            return jsonify({'message': 'User created successfully.', 'user_id': user_id}), 201
        except Exception as e:
            logger.error(f"Error creating user via API: {e}")
            return jsonify({'error': str(e)}), 500

    # Main Entry Point
    if __name__ == '__main__':
        app.run(debug=True)
