#!/usr/bin/env python3
"""
Authentication class to manage API
"""
from flask import request
from os import getenv
from typing import TypeVar, List


class Auth:
    """
    Auth base class for authentication
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Make sure path is not in excluded_paths
        """
        if path is None or excluded_paths is None or excluded_paths == []:
            return True

        if not path.endswith('/'):
            path += '/'

        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                if path.startswith(excluded_path[:-1]):
                    return False
            elif path == excluded_path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Check validity of the header
        """
        if request is None or 'Authorization' not in request.headers:
            return None

        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Get the current user based on a request
        """
        return None

    def session_cookie(self, request=None):
        """
        Return a coockie value from a request
        """
        if request is None:
            return None
        session_name = getenv('SESSION_NAME')
        return request.cookies.get(session_name, None)
