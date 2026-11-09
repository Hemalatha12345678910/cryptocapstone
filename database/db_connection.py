"""
Database Connection Manager
Provides unified database access supporting MySQL and transparent SQLite fallback.
"""

import sqlite3
import pymysql
import logging
from typing import List, Dict, Any, Optional
import config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DBConnection")

class DBConnection:
    _instance = None
    _active_engine = None

    def __init__(self):
        self.engine_preference = config.DB_ENGINE
        self._test_connection()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = DBConnection()
        return cls._instance

    def _test_connection(self):
        if self.engine_preference == "mysql":
            try:
                conn = pymysql.connect(
                    host=config.MYSQL_HOST,
                    port=config.MYSQL_PORT,
                    user=config.MYSQL_USER,
                    password=config.MYSQL_PASSWORD,
                    database=config.MYSQL_DATABASE,
                    connect_timeout=3,
                    cursorclass=pymysql.cursors.DictCursor
                )
                conn.close()
                self._active_engine = "mysql"
                logger.info("Connected to MySQL database successfully.")
                return
            except Exception as e:
                logger.warning(
                    f"MySQL connection failed ({e}). Falling back to local SQLite database at {config.SQLITE_PATH}."
                )
        self._active_engine = "sqlite"
        logger.info(f"Using SQLite database engine ({config.SQLITE_PATH}).")

    @property
    def active_engine(self) -> str:
        if self._active_engine is None:
            self._test_connection()
        return self._active_engine

    def get_raw_connection(self):
        if self.active_engine == "mysql":
            return pymysql.connect(
                host=config.MYSQL_HOST,
                port=config.MYSQL_PORT,
                user=config.MYSQL_USER,
                password=config.MYSQL_PASSWORD,
                database=config.MYSQL_DATABASE,
                autocommit=True,
                cursorclass=pymysql.cursors.DictCursor
            )
        else:
            conn = sqlite3.connect(str(config.SQLITE_PATH), timeout=20.0)
            conn.row_factory = sqlite3.Row
            return conn

    def _convert_sql(self, sql: str) -> str:
        """Translates MySQL '%s' placeholders to SQLite '?' if using SQLite."""
        if self.active_engine == "sqlite":
            # Convert standard %s to ? for SQLite parameter binding
            # Avoid replacing %% (escaped percent)
            parts = sql.split("%%")
            converted = [p.replace("%s", "?") for p in parts]
            return "%".join(converted)
        return sql

    def execute(self, sql: str, params: Optional[tuple] = None) -> int:
        """Executes INSERT/UPDATE/DELETE and returns lastrowid or affected row count."""
        raw_sql = self._convert_sql(sql)
        params = params or ()
        conn = self.get_raw_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(raw_sql, params)
            if self.active_engine == "sqlite":
                conn.commit()
                last_id = cursor.lastrowid
            else:
                last_id = cursor.lastrowid
            cursor.close()
            return last_id
        finally:
            conn.close()

    def execute_many(self, sql: str, seq_of_params: List[tuple]) -> int:
        raw_sql = self._convert_sql(sql)
        conn = self.get_raw_connection()
        try:
            cursor = conn.cursor()
            cursor.executemany(raw_sql, seq_of_params)
            if self.active_engine == "sqlite":
                conn.commit()
            cursor.close()
            return len(seq_of_params)
        finally:
            conn.close()

    def fetch_all(self, sql: str, params: Optional[tuple] = None) -> List[Dict[str, Any]]:
        raw_sql = self._convert_sql(sql)
        params = params or ()
        conn = self.get_raw_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(raw_sql, params)
            if self.active_engine == "sqlite":
                rows = cursor.fetchall()
                results = [dict(row) for row in rows]
            else:
                results = cursor.fetchall() or []
            cursor.close()
            return results
        finally:
            conn.close()

    def fetch_one(self, sql: str, params: Optional[tuple] = None) -> Optional[Dict[str, Any]]:
        raw_sql = self._convert_sql(sql)
        params = params or ()
        conn = self.get_raw_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(raw_sql, params)
            row = cursor.fetchone()
            cursor.close()
            if row is None:
                return None
            return dict(row) if self.active_engine == "sqlite" else row
        finally:
            conn.close()


# Singleton access helpers
def get_db():
    return DBConnection.get_instance()

def execute(sql: str, params: Optional[tuple] = None) -> int:
    return get_db().execute(sql, params)

def fetch_all(sql: str, params: Optional[tuple] = None) -> List[Dict[str, Any]]:
    return get_db().fetch_all(sql, params)

def fetch_one(sql: str, params: Optional[tuple] = None) -> Optional[Dict[str, Any]]:
    return get_db().fetch_one(sql, params)

