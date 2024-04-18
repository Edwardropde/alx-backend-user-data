#!/usr/bin/env python3
"""
Session based authentication
"""
from .auth import Auth
from models.user import User
from uuid import uuid4


class SessionAuth(Auth):
    """
    Class implimentation for session authentication
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        Create a session id for user_id
        """
        if user_id is None or not isinstance(user_id, str):
            return None
        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id

        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Return a user based on their session_id
        """
        if session_id is None or not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """
        Returns a user based on their cookie value
        """
        session_id = self.session_cookie(request)
        if session_id is None:
            return None
        user_id = self.user_id_for_session_id(session_id)
        return User.get(user_id)
