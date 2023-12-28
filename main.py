from flask import Flask, jsonify
from extensions import db, jwt
from auth import auth_bp
from users import user_bp
from models import User, TokenBlocklist

def create_app():
    app = Flask(__name__)
    app.config.from_prefixed_env()
    db.init_app(app)
    jwt.init_app(app)
    app.register_blueprint(auth_bp, url_prefix='/auth')
    app.register_blueprint(user_bp, url_prefix='/users') 

    @jwt.user_lookup_loader
    def user_lookup_callback(__jwt_headers, jwt_data):
        # User lookup callback to retrieve the user based on the JWT data
        identity = jwt_data['sub']
        return User.query.filter_by(username=identity).one_or_none()

    @jwt.additional_claims_loader
    def make_additional_claims(identity):
        # Additional claims loader to add custom claims to the JWT
        if identity == "Adegboyega":
            return {"is_admin": True}
        return {"is_admin": False}

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_data):
        # Callback for handling expired tokens
        return jsonify({"message": "Token has expired", "error": "token_expired"}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        # Callback for handling invalid tokens
        app.logger.error(f"Invalid token: {error}")
        return jsonify({"message": "Signature verification failed", "error": "invalid_token"}), 401
    
    @jwt.unauthorized_loader
    def missing_token_callback(error):
        # Callback for handling missing tokens
        return jsonify({"message": "Request doesn't contain a valid token", "error": "authorization_header"}), 401
    
    @jwt.token_in_blocklist_loader
    def token_in_blocklist_callback(jwt_header, jwt_data):
        # Callback for checking if a token is in the blocklist
        jti = jwt_data['jti']
        token = db.session.query(TokenBlocklist).filter(TokenBlocklist.jti == jti).scalar()
        return token is not None

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
