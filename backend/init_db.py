import sqlite3
import os

# Connect to the SQLite database file (it will create the file if it doesn't exist)
conn = sqlite3.connect('instance/users.db')
c = conn.cursor()

# Create the users table
c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
    )
''')

# Save and close
conn.commit()
conn.close()

print("✅ Database and users table created successfully.")
