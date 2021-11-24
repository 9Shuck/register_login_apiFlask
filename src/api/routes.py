"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException

from flask_jwt_extended import create_access_token, get_jwt_identity, jwt_required
from werkzeug.security import check_password_hash, generate_password_hash

api = Blueprint('api', __name__)


@api.route('/register', methods=['POST'])
def create_account():

    is_client = request.json.get('is_client', None)
    email = request.json.get('email', None)
    _password = request.json.get('_password', None)
    _is_active = request.json.get('_is_active', None)

    user = Account(
        is_client=is_client,
        email=email,
        _password = generate_password_hash(_password, method='pbkdf2:sha256', salt_length=16),
        _is_active=True
    )
    
    if user:
        try:
            user.create()
            return jsonify(user.serialize()), 201
        except exc.IntegrityError:
            return {'error': 'Something is wrong'}, 409

@api.route('/login', methods=['POST'])
def login():
    email = request.json.get('email', None)
    password = request.json.get('password', None)
    if not (email and password):
        return {'error': 'Missing information'}, 401 #BadRequest
    user = Account.get_by_email(email)
    if user and check_password_hash(user._password, password) and user._is_active:
        access_token = create_access_token(identity=user.id, expires_delta=timedelta(minutes=120))
        return {'token': access_token}, 200
    return {'error': 'Some parameter is wrong'}, 400

#Example of validation
@api.route('/users', methods=['GET'])
@jwt_required()
def get_users(id):
    users = Users.get_by_id(id)
    if not users:
        return {'error': 'Users doesnt exits'},400
    return jsonify(client.to_dict()), 200
    
#Logout on front-end clear token