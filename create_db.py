"""Optional: manually create the table in Postgres.

Usually not needed because app.py auto-creates the table at startup.
Run locally (with DATABASE_URL set) if you want:
    python create_db.py
"""
import os
import psycopg2

def main():
    db_url = os.environ.get("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL is not set")
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS responses (
            id BIGSERIAL PRIMARY KEY,
            q1 TEXT,
            q2 TEXT,
            q3 TEXT,
            q4 TEXT,
            q5 TEXT,
            q6 TEXT,
            q7 TEXT,
            q8 TEXT,
            q9 TEXT,
            q10 TEXT,
            q11 TEXT,
            submitted_at TIMESTAMPTZ DEFAULT NOW()
        );
        """
    )
    conn.commit()
    conn.close()
    print("Table ensured: responses")

if __name__ == "__main__":
    main()
