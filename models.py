# User Model
from extensions import db
from uuid import uuid4
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

class User(db.Model):  
    """
    SQLAlchemy Model representing the 'users' table.
    """
    __tablename__ = 'users'
    id = db.Column(db.String(), primary_key=True, default=str(uuid4()))
    username = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), nullable=False)  
    password = db.Column(db.Text())

    def __repr__(self):
        return f"<User {self.username}>"

    def set_password(self, password):
        """Set user password after hashing."""
        self.password = generate_password_hash(password)

    def check_password(self, password):
        """Check if the provided password matches the hashed password."""
        return check_password_hash(self.password, password)
    
    @classmethod
    def get_user_by_username(cls, username):
        """Query and retrieve a user by their username."""
        return cls.query.filter_by(username=username).first()
    
    def save_user(self):
        """Save the user instance to the database."""
        db.session.add(self)
        db.session.commit()

    def delete_user(self):
        """Delete the user instance from the database."""
        db.session.delete(self)
        db.session.commit()

# TokenBlocklist Model
class TokenBlocklist(db.Model):
    """
    SQLAlchemy Model representing the 'token_blocklist' table for revoked JWTs.
    """
    id = db.Column(db.Integer(), primary_key=True)
    jti = db.Column(db.String(), nullable=False)
    create_at = db.Column(db.DateTime(), default=datetime.utcnow)

    def __repr__(self):
        return f"<TokenBlocklist: {self.jti}>"
    
    def save(self):
        """Save the token blocklist instance to the database."""
        db.session.add(self)
        db.session.commit()
