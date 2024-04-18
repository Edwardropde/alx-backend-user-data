#!/usr/bin/env python3
"""
Basic Authentication class
"""
from .auth import Auth
from typing import TypeVar, Tuple
from models.user import User
import base64


class BasicAuth (Auth):
    """
    Basic authentication
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """
        Extract base64 authorization string from HTTTP Header
        """
        if authorization_header is None or not isinstance(authorization_header,
                                                          str):
            return None

        if not authorization_header.startswith('Basic '):
            return None

        return authorization_header.split(' ')[1]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header:
                                           str) -> str:
        """
        Decode Base64 authorization string
        """
        if base64_authorization_header is None \
                or not isinstance(base64_authorization_header, str):
            return None

        try:
            return base64.b64decode(base64_authorization_header)\
                    .decode('utf-8')
        except Exception as e:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header:
                                 str) -> Tuple[str, str]:
        """
        Extract the user credentials from the header
        """
        if decoded_base64_authorization_header is None or \
                not isinstance(decoded_base64_authorization_header, str):
            return None, None

        if ':' not in decoded_base64_authorization_header:
            return None, None

        creditials = decoded_base64_authorization_header.split(':', 1)
        return creditials[0], creditials[1]

    def user_object_from_credentials(self,
                                     user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
        Returns a User based on their email and password
        """
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        users = User.search({'email': user_email})
        if not users:
            return None

        for user in users:
            if not user.is_valid_password(user_pwd):
                return None
            return user

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Get current user
        """
        header = self.authorization_header(request)
        encoded_str = self.extract_base64_authorization_header(header)
        decoded_str = self.decode_base64_authorization_header(encoded_str)
        user_email, user_pwd = self.extract_user_credentials(decoded_str)
        user = self.user_object_from_credentials(user_email, user_pwd)
        return user
