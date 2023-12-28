from marshmallow import fields, Schema

class UserSchema(Schema):
    id = fields.String(dump_only=True)  # Assuming 'id' is generated and should not be provided during user creation
    username = fields.String(required=True)
    email = fields.Email(required=True)
