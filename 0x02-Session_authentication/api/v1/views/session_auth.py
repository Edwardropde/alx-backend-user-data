#!/usr/bin/env python3
"""
View for session authentication
"""
from flask import request, jsonify, make_response
from api.v1.views import app_views
from models.user import User
from os import getenv

@app_views.route("/auth_session/login", methods= ["POST"], strict_slashes=False)
def login_session():
    """
    Post the login details
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if not email:
        return jsonify({ "error": "email missing" }), 400
    if not password:
        return jsonify({ "error": "password missing" }), 400

    users = User.search({'email': email})
    if not users:
        return jsonify({ "error": "no user found for this email" }), 404

    for user in users:
        if not User.is_valid_password(user, password):
            return jsonify({ "error": "wrong password" } ), 401
        from api.v1.app import auth
        session_id = auth.create_session(user.id)
        response = make_response(user.to_json())
        response.set_cookie(getenv('SESSION_NAME'), session_id)
        return response
