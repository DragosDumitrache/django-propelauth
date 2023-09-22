import logging

import requests
from django.conf import settings
from django.contrib.auth import authenticate, logout
from django.contrib.auth.middleware import PersistentRemoteUserMiddleware
from django.shortcuts import redirect
from propelauth_py import UnauthorizedException

from django_propelauth.views import raw_auth, AUTH_URL, API_KEY

logger = logging.getLogger(__name__)

URLS = ['/auth/logout', '/auth/callback']


class SimpleMiddleware(PersistentRemoteUserMiddleware):
    def __init__(self, get_response):
        super().__init__(get_response)

    def __call__(self, request):
        user = request.user
        if not (user and user.is_authenticated and user.email) and request.path in URLS:
            return self.get_response(request)

        logger.debug('simple_middleware.start')
        access_token = request.COOKIES.get("pa-access-token")
        refresh_token = request.COOKIES.get("pa-refresh-token")
        logger.error('access_token.refresh token=%s refresh_token=%s path=%s', access_token, refresh_token,
                     request.path)

        if access_token:
            try:
                bearer_token = f'Bearer {access_token}'
                # logger.debug(event='auth.access_token.refresh', state='success')
                user = raw_auth.validate_access_token_and_get_user(bearer_token)
                request.session['propelauth_user'] = user.user_id
                # authenticate(request)
            except UnauthorizedException as e:
                logger.error('auth.access_token.refresh')
            except Exception as e:
                logger.error('auth.access_token.other_error')
            logger.debug('access_token.complete')
        if refresh_token:
            url = f"{AUTH_URL}/api/backend/v1/refresh_token"
            bearer_token = f"Bearer {API_KEY}"
            # logger.debug(event='refresh_token.refresh', bearer_token=bearer_token)
            auth_response = requests.post(url, json={"refresh_token": refresh_token}, headers={
                "Authorization": bearer_token,
            })

            if auth_response.status_code == 200:
                json_response = auth_response.json()
                access_token = json_response["access_token"]["access_token"]
                refresh_token = json_response["refresh_token"]
        if access_token:
            try:
                bearer_token = f'Bearer {access_token}'
                user = raw_auth.validate_access_token_and_get_user(bearer_token)
                request.session['propelauth_user'] = user.user_id
                # authenticate(request)
            except UnauthorizedException as e:
                logger.error('user.not_logged_in user=%s message=%s', request.session.get('propelauth_user'), e.message)
                return redirect('/auth/login', status_code=401)
            except Exception as e:
                logger.error('some_other_exception')

        authenticate(request)
        logger.error('Before we process the request user=%s', request.user.is_authenticated)
        response = self.get_response(request)
        if access_token is not None and refresh_token is not None:
            response.set_cookie("pa-access-token", access_token, max_age=1800, secure=True, httponly=True,
                                samesite="Lax")
            response.set_cookie("pa-refresh-token", refresh_token, max_age=1209600, secure=True, httponly=True,
                                samesite="Lax")
        else:
            response.set_cookie("pa-access-token", "", max_age=0, secure=True, httponly=True, samesite="Lax")
            response.set_cookie("pa-refresh-token", "", max_age=0, secure=True, httponly=True, samesite="Lax")

        # Code to be executed for each request/response after
        # the view is called.
        logger.debug('simple_middleware.finish')
        return response
        # return self.get_response(request)
