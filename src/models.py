
from flask_login import UserMixin

from database import get_user_by_id


class User(UserMixin):
    """Represent an application user for Flask-Login."""

    def __init__(self, user_record):
        self.id = str(user_record["id"])
        self.username = user_record["username"]
        self.role = user_record["role"]

    @staticmethod
    def get(user_id):
        """Load a user from the database by ID."""
        try:
            record = get_user_by_id(int(user_id))
        except (TypeError, ValueError):
            return None

        if record is None:
            return None

        return User(record)

