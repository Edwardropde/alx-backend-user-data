#!/usr/bin/env python3
"""
Module for authentication-related rooutines
"""
import bcrypt
import uuid
from sqlalchemy.orm.exc import NoResultFound
from db import DB
from user import User


class Auth:
    """
    Auth class to interact with the authentication database
    """

    def __init__(self):
        """Constructor function"""
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        """Hashes the input password string using bcrypt.hashpw."""
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode(), salt)
        return hashed_password

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user with the provided email and password."""
        try:
            existing_user = self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = self._hash_password(password)
            new_user = self._db.add_user(email, hashed_password)
            return new_user

    def valid_login(self, email: str, password: str) -> bool:
        """Checks if the provided email and password are valid for login."""
        try:
            user = self._db.find_user_by(email=email)
            # Check if the provided password matches the hashed password
            return bcrypt.checkpw(password.encode(), user.hashed_password)
        except NoResultFound:
            return False

    def _generate_uuid(self) -> str:
        """Generates a new UUID and returns its string representation."""
        return str(uuid.uuid4())

    def create_session(self, email: str) -> str:
        """Creates a session for the user with the given email."""
        try:
            user = self._db.find_user_by(email=email)
            session_id = self._generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """Returns the user corresponding to given session ID, or None"""
        if not session_id:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Updates the session ID of the user with the given user_id."""
        self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """Generates a reset password token for user with given email."""
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError(f"User {email} does not exist")

        reset_token = str(uuid.uuid4())
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates the password for the user with the given reset token."""
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = self._hash_password(password)
            update = self._db.update_user()
            update(user.id, hashed_password=hashed_password, reset_token=None)
        except NoResultFound:
            raise ValueError("Invalid reset token")
