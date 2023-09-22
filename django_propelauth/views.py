import logging
import random
import string

import propelauth_py
import requests
from django.contrib.auth import logout
from django.http import HttpResponse
from django.shortcuts import redirect
# Create your views here.
from rest_framework.decorators import api_view

from django_propelauth import user_service

AUTH_URL = 'https://3344880.propelauthtest.com'
API_KEY = '799f44f1b529418c208dd81706bfdeab42075e765015dadacc8eb993c06ee441afdf3eddb9f202fd34715011c79867ba'
AUTH_CLIENT_ID = '636b2943-c66e-48f2-8e46-b5e0bf9e5fe6'
AUTH_CLIENT_SECRET = 'ea7ea520fb8c752afa8f700119c5216c2e1f9ccb4c5f4062b88259d7cf446af7ad7c37e48dbe5bd079ecb7e1ceb283f5'
AUTH_REDIRECT_URI = 'http://localhost:8080/auth/callback'

raw_auth = propelauth_py.init_base_auth(AUTH_URL, API_KEY)

logger = logging.getLogger(__name__)

def get_auth_url(state):
    authorize_url = f"{AUTH_URL}/propelauth/authorize?response_type=code&client_id={AUTH_CLIENT_ID}&redirect_uri={AUTH_REDIRECT_URI}&state={state}"
    return authorize_url


@api_view(['GET'])
def whoami(request):
    return redirect('/', request=request)


@api_view(['GET'])
def index(request):
    if request.user.is_authenticated:
        return HttpResponse(f'{request.user.email} {request.session.get("propelauth_user")} {request.user.is_authenticated}')
    return HttpResponse(f'{request.user} {request.session.get("propelauth_user")} {request.user.is_authenticated}')

@api_view(['GET'])
def login(request):
    state = "".join(random.choices(string.ascii_letters + string.digits, k=64))
    authorize_url = get_auth_url(state)
    response = redirect(authorize_url)
    # logger.info(event='auth.login', redirect_to=authorize_url)
    response.set_cookie('pa-state', state, path='/', httponly=True, samesite='Lax', secure=True)
    return response


@api_view(['GET'])
def signup(request):
    state = "".join(random.choices(string.ascii_letters + string.digits, k=64))
    authorize_url = f"{get_auth_url(state)}&signup=true"
    response = redirect(authorize_url)
    # logger.info(event='auth.signup', redirect_to=authorize_url)
    response.set_cookie('pa-state', state, httponly=True, samesite='Lax', secure=True)
    return response


@api_view(['GET', 'POST'])
def callback(request):
    state_cookie = request.COOKIES.get("pa-state")
    if not state_cookie or len(state_cookie) != 64:
        # logger.info(event='auth.callback.state_cookie.missing', valid=False, redirect_to='/auth/login')
        return redirect("/auth/login", 302)
    state = request.query_params.get("state")
    if state != state_cookie:
        # logger.info(event='auth.callback.state_cookie_mismatch', state=state, state_cookie=state_cookie, redirect_to='/auth/login')
        return redirect("/auth/login", 302)

    code = request.query_params.get("code")
    if not code:
        # logger.info(event='auth.callback.code.missing', redirect_to='/auth/login')
        return redirect("/auth/login", 302)

    callback_body = {
        "client_id": AUTH_CLIENT_ID,
        "client_secret": AUTH_CLIENT_SECRET,
        "redirect_uri": AUTH_REDIRECT_URI,
        "grant_type": "authorization_code",
        "code": code
    }

    token_response = requests.post(f"{AUTH_URL}/propelauth/token", json=callback_body,
                                   headers={
                                       "Authorization": f"Bearer {API_KEY}",
                                   })
    # logger.info(event='auth.create_token', auth_url=AUTH_URL, redirect_to=AUTH_REDIRECT_URI, status=token_response.status_code)

    if token_response.status_code == 401:
        # logger.info(event='auth.unauthorised', status=token_response.status_code)
        return "An unexpected error occurred."
    elif token_response.status_code != 200:
        # logger.info(event='auth.unexpected_error', status=token_response.status_code)
        return "An unexpected error occurred."

    json_response = token_response.json()
    access_token = json_response["access_token"]
    refresh_token = json_response["refresh_token"]

    user = raw_auth.validate_access_token_and_get_user("Bearer " + access_token)
    user_service.upsert_user(email=user.email, propelauth_id=user.user_id)
    r = redirect('/', status=302)
    r.set_cookie("pa-access-token", access_token, max_age=1800, secure=True, httponly=True, samesite="Lax")
    r.set_cookie("pa-refresh-token", refresh_token, max_age=1209600, secure=True, httponly=True, samesite="Lax")
    return r


@api_view(['GET'])
def logout_view(request):
    logout(request)
    response = redirect("/", status=302)
    logger.error('auth.logout redirect_to=/')
    response.set_cookie("pa-access-token", "", max_age=0, secure=True, httponly=True, samesite="Lax")
    response.set_cookie("pa-refresh-token", "", max_age=0, secure=True, httponly=True, samesite="Lax")
    return response
