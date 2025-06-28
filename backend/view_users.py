import sqlite3

# Connect to your SQLite database inside the instance folder
conn = sqlite3.connect('instance/users.db')

# Create a cursor to execute SQL commands
cursor = conn.cursor()

# Run a SELECT query to get all user data
cursor.execute("SELECT * FROM users")

# Fetch all results from the table
users = cursor.fetchall()

# Print each user's data
for user in users:
    print(user)

# Close the database connection
conn.close()
