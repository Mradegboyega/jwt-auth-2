from flask import Blueprint, app, jsonify, request
from models import User, TokenBlocklist
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, current_user, jwt_required, get_jwt, get_jwt_identity, jwt_manager

# Create a Flask Blueprint for authentication
auth_bp = Blueprint('auth', __name__)

# Register endpoint for user registration
@auth_bp.route('/register', methods=['POST'])
def register_user(): 
    # Extract user data from the JSON request
    data = request.get_json()

    # Check if the user already exists
    user = User.get_user_by_username(username=data.get('username'))
    if user is not None:
        return jsonify({"error": "User already exists"}), 403
    
    # Create a new user, set the password, and save to the database
    new_user = User(username=data.get('username'), email=data.get('email'))
    new_user.set_password(password=data.get('password'))
    new_user.save_user()

    # Return success message
    return jsonify({"message": "User Created"}), 201

# Login endpoint
@auth_bp.post('/login')
def login_user():
    # Extract user data from the JSON request
    data = request.get_json()

    # Check if the provided username and password are valid
    user = User.get_user_by_username(username=data.get('username'))
    if user and user.check_password(password=data.get('password')):
        # Create new access and refresh tokens
        access_token = create_access_token(identity=user.username)
        refresh_token = create_refresh_token(identity=user.username)

        # Return tokens in a JSON response
        return jsonify({"message": 'Logged in', "tokens": {"access": access_token, "refresh": refresh_token}}), 200
    
    # Return error for invalid username or password
    return jsonify({"error": "Invalid username or password"}), 401

# Endpoint to retrieve details of the current user
@auth_bp.get('/whoami')
@jwt_required()  # Ensure a valid JWT is required to access the endpoint
def whoami():
    # Return JSON response with user details
    return jsonify({"message": "You accessed the 'whoami' endpoint successfully!", 
                    "user_details": {"username": current_user.username, "email": current_user.email}})

# Token refresh endpoint
@auth_bp.get('/refresh')
@jwt_required(refresh=True)  # Ensure a valid refresh token is required to access the endpoint
def refresh_access():
    # Extract identity from the refresh token and create a new access token
    identity = get_jwt_identity()
    new_access_token = create_access_token(identity=identity)

    # Return the new access token in a JSON response
    return jsonify({"access_token": new_access_token})

# Logout endpoint with token type verification
@auth_bp.get('/logout')
@jwt_required(verify_type=False)  # Ensure a valid JWT is required to access the endpoint
def logout_user():
    # Get the JWT from the request
    jwt_token = get_jwt()

    # Extract the JWT's unique identifier (jti) and token type
    jti = jwt_token['jti']
    token_type = jwt_token['type']

    # Create a TokenBlocklist instance with the jti and save it to the database
    token_blocklist = TokenBlocklist(jti=jti)
    token_blocklist.save()

    # Return a JSON response indicating successful logout with token type information
    return jsonify({
        "message": f"{token_type} token revoked"
    }), 200

