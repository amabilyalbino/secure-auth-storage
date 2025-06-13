from logger import configure_logging
import logging
import psycopg2
from settings import DB_NAME, DB_USER, DB_PASSWORD, DB_HOST

configure_logging()
logger = logging.getLogger(__name__)

def get_connection():
    try:
        return psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=5432
        )
    except psycopg2.OperationalError as e:
        logger.error(f"Failed to connect to database: {e}")
        raise

def select_db(query: str, vars, func_name: str):
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query, vars)
                return cur.fetchall()
    except psycopg2.Error as e:
        logger.error(f"Database error during {func_name}: {e}")
        raise

def insert_db(query: str, vars, func_name:str):
    try:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(query,vars)
                conn.commit()
               
    except psycopg2.Error as e:
        logger.error(f"Database error during {func_name}: {e}")
        raise
def setup_user_table():
    insert_db(
        "CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, salt TEXT NOT NULL, hashed_password TEXT NOT NULL);",
        (),
        "setup_user_table"
    )
    logger.info("Users table initialized.")

