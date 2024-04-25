#!/usr/bin/env python3
"""
Flask app with user authentication features.
"""

from flask import Flask, jsonify, request, abort, redirect, make_response
from auth import Auth

app = Flask(__name__)
auth = Auth()


@app.route("/", methods=['GET'], strict_slashes=False)
def welcome() -> str:
    """
    Welcome route returning a JSON payload
    """
    return jsonify({"message": "Bienvenue"})


@app.route("/users", methods=["POST"])
def register() -> str:
    """
    Endpoint to register a user
    """
    try:
        email = request.form.get("email")
        password = request.form.get("password")
        # Attempt to register the user
        user = auth.register_user(email, password)
        # User successfully registered
        return jsonify({"email": user.email, "message": "user created"}), 200
    except ValueError as err:
        # User already registered
        return jsonify({"message": "email already registered"}), 400


@app.route("/sessions", methods=["POST"])
def login():
    email = request.form.get("email")
    password = request.form.get("password")
    if not email or not password:
        abort(400)
    if not auth.valid_login(email, password):
        abort(401)
    session_id = auth.create_session(email)
    if not session_id:
        abort(500)
    response = make_response(
        jsonify({"email": email, "message": "logged in"}), 200)
    response.set_cookie("session_id", session_id)
    return response


@app.route("/sessions", methods=["DELETE"])
def logout():
    session_id = request.cookies.get("session_id")
    if not session_id:
        return jsonify({"error": "Session ID not provided"}), 400
    user = auth.get_user_from_session_id(session_id)
    if user:
        auth.destroy_session(user.id)
        return redirect("/")
    else:
        return jsonify({"error": "User not found"}), 403


@app.route("/profile")
def profile():
    session_id = request.cookies.get("session_id")
    if not session_id:
        return jsonify({"error": "Session ID not provided"}), 403
    user = auth.get_user_from_session_id(session_id)
    if user:
        return jsonify({"email": user.email}), 200
    else:
        return jsonify({"error": "User not found"}), 403


@app.route("/reset_password", methods=["POST"])
def reset_password():
    email = request.form.get("email")
    try:
        reset_token = auth.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token}), 200
    except ValueError as e:
        return str(e), 403


@app.route("/reset_password", methods=["PUT"])
def update_password():
    email = request.form.get("email")
    reset_token = request.form.get("reset_token")
    new_password = request.form.get("new_password")
    try:
        auth.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
