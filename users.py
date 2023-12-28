from sqlalchemy.exc import SQLAlchemyError, IntegrityError
from flask import Blueprint, request, jsonify
from models import User
from schemas import UserSchema
from flask_jwt_extended import jwt_required, get_jwt, current_user

user_bp = Blueprint(
    'users',
    __name__
)

@user_bp.route('/all_users', methods=['GET'])
@jwt_required()
def get_all_users():

    claims = get_jwt()

    if claims.get('is_admin') == True:

        try:
            # Get the page and per_page parameters from the request's query string
            page = request.args.get('page', default=1, type=int)
            per_page = request.args.get('per_page', default=3, type=int)

            # Query the User table, paginate the results, and store in the 'users' variable
            users = User.query.paginate(
                page=page,
                per_page=per_page
            )

            # Serialize the paginated User objects using UserSchema
            result = UserSchema().dump(users.items, many=True)

            # Return the serialized result as JSON along with a 200 status code
            return jsonify(result), 200

        except IntegrityError as integrity_error:
            # Handle integrity constraint violations (e.g., unique constraint)
            return jsonify({"error": f"IntegrityError: {str(integrity_error)}"}), 500

        except SQLAlchemyError as e:
            # Handle other database-related exceptions
            return jsonify({"error": f"SQLAlchemyError: {str(e)}"}), 500
        
    return jsonify({"message":"Youre not authorised to access this place"}), 401
