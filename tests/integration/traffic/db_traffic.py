#!/usr/bin/env python3
"""Generate deterministic MySQL and PostgreSQL traffic with PII."""

import sys
import time


def run_mysql():
    import pymysql

    print("[mysql] Connecting to MySQL...")
    last_error = None
    for attempt in range(60):
        try:
            conn = pymysql.connect(
                host="mysql",
                port=3306,
                user="test",
                password="testpass",
                database="testdb",
                connect_timeout=5,
                ssl_disabled=True,
            )
            break
        except Exception as exc:
            last_error = exc
            time.sleep(1)
    else:
        print(
            f"[mysql] Failed to connect after 60 attempts: {last_error}",
            file=sys.stderr,
        )
        return False

    cursor = conn.cursor()

    # SELECT with PII data
    cursor.execute("SELECT name, email, ssn FROM users WHERE id = 1")
    row = cursor.fetchone()
    print(f"[mysql] SELECT user 1: {row}")

    # SELECT all
    cursor.execute("SELECT * FROM users")
    rows = cursor.fetchall()
    print(f"[mysql] SELECT all: {len(rows)} rows")

    # INSERT with PII (email, SSN, phone)
    pii_inserts = [
        ("Eve Adams", "eve@secret.com", "555-66-7777", "+1-555-666-7777"),
        ("Frank Castle", "frank.castle@punisher.org", "111-22-3333", "(555) 987-6543"),
        ("Grace Hopper", "grace.hopper@navy.mil", "444-55-6666", "+1-202-555-0199"),
    ]
    for name, email, ssn, phone in pii_inserts:
        cursor.execute(
            "INSERT INTO users (name, email, ssn, phone) VALUES (%s, %s, %s, %s)",
            (name, email, ssn, phone),
        )
    conn.commit()
    print(f"[mysql] INSERT {len(pii_inserts)} rows with PII complete")

    # SELECT with credit card and IP data (if columns exist)
    cursor.execute("SELECT name, email FROM users WHERE email LIKE '%@secret.com'")
    rows = cursor.fetchall()
    print(f"[mysql] SELECT by email pattern: {len(rows)} rows")

    # Query with PII in WHERE clause
    cursor.execute("SELECT * FROM users WHERE ssn = '123-45-6789'")
    rows = cursor.fetchall()
    print(f"[mysql] SELECT by SSN: {len(rows)} rows")

    cursor.close()
    conn.close()
    print("[mysql] MySQL traffic complete.")
    return True


def run_postgres():
    import psycopg2

    print("[postgres] Connecting to PostgreSQL...")
    last_error = None
    for attempt in range(30):
        try:
            conn = psycopg2.connect(
                host="postgres",
                port=5432,
                user="postgres",
                password="testpass",
                dbname="testdb",
                connect_timeout=5,
                sslmode="disable",
            )
            break
        except Exception as exc:
            last_error = exc
            time.sleep(1)
    else:
        print(
            f"[postgres] Failed to connect after 30 attempts: {last_error}",
            file=sys.stderr,
        )
        return False

    cursor = conn.cursor()

    # SELECT with PII
    cursor.execute("SELECT name, email, ssn FROM users WHERE id = 1")
    row = cursor.fetchone()
    print(f"[postgres] SELECT user 1: {row}")

    # Parameterized query with PII
    cursor.execute(
        "SELECT * FROM users WHERE email = %s", ("alice@example.com",)
    )
    rows = cursor.fetchall()
    print(f"[postgres] SELECT by email: {len(rows)} rows")

    # INSERT with PII
    cursor.execute(
        "INSERT INTO users (name, email, ssn, phone) VALUES (%s, %s, %s, %s)",
        ("Diana Prince", "diana@themyscira.gov", "222-33-4444", "+1-555-000-1234"),
    )
    conn.commit()
    print("[postgres] INSERT with PII complete")

    # Query with PII in WHERE clause
    cursor.execute("SELECT * FROM users WHERE ssn = '123-45-6789'")
    rows = cursor.fetchall()
    print(f"[postgres] SELECT by SSN: {len(rows)} rows")

    cursor.close()
    conn.close()
    print("[postgres] PostgreSQL traffic complete.")
    return True


def run():
    mysql_ok = run_mysql()
    postgres_ok = run_postgres()
    if not mysql_ok or not postgres_ok:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
