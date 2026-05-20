import os
import psycopg2
from psycopg2.extras import RealDictCursor


def get_db():
    """
    Return a new psycopg2 connection using DATABASE_URL from the environment.
    Always close the connection in a finally block after use.
    Never hardcode credentials here — they live only in .env / environment vars.
    """
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        raise RuntimeError(
            "DATABASE_URL environment variable is not set. "
            "Add it to your .env file and never commit that file to git."
        )
    return psycopg2.connect(database_url, cursor_factory=RealDictCursor)