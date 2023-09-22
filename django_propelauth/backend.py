import logging
from typing import Optional

from django.conf import settings
from django.contrib.auth import login
from rest_framework.authentication import BaseAuthentication

from django_propelauth import user_service
from django_propelauth.models import User

logger = logging.getLogger(__name__)


class PropelAuthBackend(BaseAuthentication):
    def authenticate(self, request):
        user_id = request.session.get('propelauth_user')
        logger.error('user.authenticate user_id=%s', user_id)
        if not user_id:
            return None
        user: Optional[User] = self.get_user(user_id)
        if user is not None:
            logger.error('user.retrieve user_id=%s, user_email=%s', user_id, user.email)
            login(request, user, backend=settings.AUTHENTICATION_BACKENDS[1])
            return user
        return None

    def get_user(self, user_id):
        user: Optional[User] = user_service.get_user_by_propelauth_id(user_id)
        return user
