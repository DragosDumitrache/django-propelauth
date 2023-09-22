import logging
from typing import Optional

from django.db import transaction

from django_propelauth.models import User

logger = logging.getLogger(__name__)


def create_user(email: str, propelauth_id: str) -> User:
    """Creates a new user.

    Args:
        email (str): The user's email.
        propelauth_id (str): The PropelAuth id of the user.

    Returns:
        User: The created user.
    """
    new_user, created = User.objects.get_or_create(email=email)
    new_user.propelauth_id = propelauth_id
    try:
        new_user.save()
        return new_user
    except Exception as e:
        if created:
            new_user.delete()
        raise e


def get_user_by_id(id: int) -> Optional[User]:
    """Retrieves a user by their id.

    Args:
        id (int): The id of the user to retrieve.

    Returns:
        Optional[User]: The retrieved user, or None if no user is found.
    """
    return User.objects.filter(id=id).first()


def get_user_by_propelauth_id(propelauth_id: str) -> Optional[User]:
    """Retrieves a user by their PropelAuth id.

    Args:
        propelauth_id (str): The PropelAuth id of the user to retrieve.

    Returns:
        Optional[User]: The retrieved user, or None if no user is found.
    """
    return User.objects.filter(propelauth_id=propelauth_id).first()


def get_user_by_email(email: str) -> Optional[User]:
    """Retrieves a user by their email.

    Args:
        email (str): The email of the user to retrieve.

    Returns:
        Optional[User]: The retrieved user, or None if no user is found.
    """
    return User.objects.filter(email=email).first()


@transaction.atomic
def upsert_user(email: Optional[str] = None, propelauth_id: Optional[str] = None) -> User:
    """Creates or updates a user.

    If a user with the provided email or PropelAuth id exists, updates their email and/or PropelAuth id.
    If no such user exists, creates a new user with the provided email and PropelAuth id.

    Args:
        email (Optional[str]): The user's email.
        propelauth_id (Optional[str]): The PropelAuth id of the user.

    Returns:
        User: The created or updated user.

    Raises:
        ValueError: If neither email nor PropelAuth id are provided.
    """
    if not email and not propelauth_id:
        raise ValueError("Either email or PropelAuth id must be provided")

    user = None
    if email:
        user = get_user_by_email(email)
    if not user and propelauth_id:
        user = get_user_by_propelauth_id(propelauth_id)

    if not user:
        user, created = User.objects.get_or_create(email=email, propelauth_id=propelauth_id)
        user.save()
    else:
        if email is not None:
            user.email = email
        if propelauth_id is not None:
            user.propelauth_id = propelauth_id

    try:
        with transaction.atomic():
            user.save()
        return user
    except Exception as e:
        logger.info('transaction.error message=%s', e.__str__())
        raise e
